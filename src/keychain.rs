use std::{ptr, thread};

use color_eyre::eyre::{eyre, Error};
use core_foundation::{
    base::{CFGetTypeID, CFRelease, TCFType as _, ToVoid},
    boolean::CFBoolean,
    data::{CFData, CFDataRef},
    dictionary::CFMutableDictionary,
    error::{CFError, CFErrorRef},
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    key::{Algorithm, SecKey},
};
use security_framework_sys::{
    access_control::{
        kSecAccessControlBiometryAny, kSecAccessControlDevicePasscode, kSecAccessControlOr,
        kSecAccessControlPrivateKeyUsage,
    },
    base::{errSecItemNotFound, errSecSuccess, SecKeyRef},
    item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel,
        kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey,
        kSecPrivateKeyAttrs, kSecReturnRef,
    },
    key::SecKeyAlgorithm,
    keychain_item::SecItemCopyMatching,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const KEY_LABEL: &str = "desu.tei.bw-ssh-agent.main-key";

extern "C" {
    pub static kSecAttrApplicationTag: CFStringRef;
    pub static kSecUseOperationPrompt: CFStringRef;
    pub fn SecKeyCreateEncryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        plaintext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub fn SecKeyCreateDecryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        ciphertext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
}

#[derive(Debug)]
enum KeychainCommand {
    EnsureKeypair,
    EncryptData(Vec<u8>),
    DecryptData(Vec<u8>),
    Terminate,
}

enum KeychainResponse {
    Ok,
    OkWithData(Vec<u8>),
    Err(Error),
}

pub struct KeychainThread {
    tx: tokio::sync::mpsc::Sender<KeychainResponse>,
    rx: std::sync::mpsc::Receiver<KeychainCommand>,
    key: Option<SecKey>,
    pub_key: Option<SecKey>,
}

impl KeychainThread {
    pub fn thread_loop(mut self) {
        loop {
            let command = match self.rx.recv() {
                Ok(command) => command,
                Err(_) => break,
            };

            match command {
                KeychainCommand::Terminate => {
                    self.key = None;
                    self.pub_key = None;
                    break;
                }
                KeychainCommand::EnsureKeypair => {
                    if let Err(err) = self.ensure_keypair() {
                        self.tx.blocking_send(KeychainResponse::Err(err)).unwrap();
                    } else {
                        self.tx.blocking_send(KeychainResponse::Ok).unwrap();
                    }
                }
                KeychainCommand::EncryptData(data) => {
                    match self.encrypt_or_decrypt_data(true, data) {
                        Ok(data) => {
                            self.tx
                                .blocking_send(KeychainResponse::OkWithData(data))
                                .unwrap();
                        }
                        Err(err) => {
                            self.tx.blocking_send(KeychainResponse::Err(err)).unwrap();
                        }
                    }
                }
                KeychainCommand::DecryptData(data) => {
                    match self.encrypt_or_decrypt_data(false, data) {
                        Ok(data) => {
                            self.tx
                                .blocking_send(KeychainResponse::OkWithData(data))
                                .unwrap();
                        }
                        Err(err) => {
                            self.tx.blocking_send(KeychainResponse::Err(err)).unwrap();
                        }
                    }
                }
            }
        }
    }

    pub fn encrypt_or_decrypt_data(
        &mut self,
        encrypt: bool,
        data: Vec<u8>,
    ) -> color_eyre::Result<Vec<u8>> {
        if encrypt {
            let Some(pub_key) = &self.pub_key else {
                return Err(eyre!("No public key available"));
            };

            unsafe {
                self.encrypt_data(
                    &pub_key,
                    Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                    &data,
                )
            }
        } else {
            let Some(key) = &self.key else {
                return Err(eyre!("No private key available"));
            };

            unsafe {
                self.decrypt_data(
                    &key,
                    Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                    &data,
                )
            }
        }
    }

    unsafe fn find_priv_key(&self) -> color_eyre::Result<Option<SecKey>> {
        let mut ret = ptr::null();
        let res = SecItemCopyMatching(
            CFMutableDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrLabel),
                    CFString::new(KEY_LABEL).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyClass),
                    CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecReturnRef),
                    CFBoolean::true_value().as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecUseOperationPrompt),
                    CFString::new("Please enter your passcode").as_CFType(),
                ),
            ])
            .as_concrete_TypeRef(),
            &mut ret,
        );

        if res != errSecSuccess {
            if res == errSecItemNotFound {
                return Ok(None);
            }

            return Err(eyre!("SecItemCopyMatching failed: {res}"));
        }

        let type_id = CFGetTypeID(ret);
        if type_id != SecKey::type_id() {
            return Ok(None);
        }

        let key = SecKey::wrap_under_get_rule(ret as *mut _);
        CFRelease(ret);

        Ok(Some(key))
    }

    unsafe fn encrypt_data(
        &self,
        key: &SecKey,
        algo: Algorithm,
        data: &[u8],
    ) -> color_eyre::Result<Vec<u8>> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateEncryptedData(
                key.to_void() as _,
                algo.into(),
                CFData::from_buffer(data.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            let err = unsafe { CFError::wrap_under_create_rule(error) };
            return Err(eyre!("Failed to encrypt data: {err}"));
        } else {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        }
    }

    unsafe fn decrypt_data(
        &self,
        key: &SecKey,
        algo: Algorithm,
        data: &[u8],
    ) -> color_eyre::Result<Vec<u8>> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateDecryptedData(
                key.to_void() as _,
                algo.into(),
                CFData::from_buffer(data.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            let err = unsafe { CFError::wrap_under_create_rule(error) };
            return Err(eyre!("Failed to encrypt data: {err}"));
        } else {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        }
    }

    fn ensure_keypair(&mut self) -> color_eyre::Result<()> {
        let found = unsafe { self.find_priv_key() }?;

        if found.is_some() {
            self.key = found;
            self.pub_key = self.key.as_ref().unwrap().public_key();
            return Ok(());
        }

        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlBiometryAny
                | kSecAccessControlPrivateKeyUsage
                | kSecAccessControlDevicePasscode
                | kSecAccessControlOr,
        )?;

        let key = SecKey::generate(
            CFMutableDictionary::from_CFType_pairs(&[
                (
                    unsafe { kSecAttrKeyType }.to_void(),
                    unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
                ),
                (
                    unsafe { kSecAttrKeySizeInBits }.to_void(),
                    CFNumber::from(256).to_void(),
                ),
                (
                    unsafe { kSecAttrTokenID }.to_void(),
                    unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
                ),
                (
                    unsafe { kSecPrivateKeyAttrs }.to_void(),
                    CFMutableDictionary::from_CFType_pairs(&[
                        (
                            unsafe { kSecAttrIsPermanent }.to_void(),
                            CFBoolean::true_value().to_void(),
                        ),
                        (
                            unsafe { kSecAttrLabel }.to_void(),
                            CFString::new(KEY_LABEL).to_void(),
                        ),
                        (
                            unsafe { kSecAttrAccessControl }.to_void(),
                            access_control.to_void(),
                        ),
                    ])
                    .to_immutable()
                    .to_void(),
                ),
            ])
            .to_immutable(),
        )
        .map_err(|err| eyre!("Failed to generate key: {err}"))?;

        self.key = Some(key);
        self.pub_key = Some(self.key.as_ref().unwrap().public_key().unwrap());

        Ok(())
    }
}

pub struct Keychain {
    thread: thread::JoinHandle<()>,
    tx: std::sync::mpsc::Sender<KeychainCommand>,
    rx: tokio::sync::mpsc::Receiver<KeychainResponse>,
    mutex: Mutex<()>,
}

impl Keychain {
    pub fn start() -> Self {
        let (tx_my, rx) = std::sync::mpsc::channel::<KeychainCommand>();
        let (tx, rx_my) = tokio::sync::mpsc::channel::<KeychainResponse>(100);

        let thread = KeychainThread {
            tx,
            rx,
            key: None,
            pub_key: None,
        };
        let handle = thread::spawn(move || thread.thread_loop());

        Self {
            thread: handle,
            tx: tx_my,
            rx: rx_my,
            mutex: Mutex::new(()),
        }
    }

    pub fn terminate(self) {
        let _guard = self.mutex.lock();

        self.tx.send(KeychainCommand::Terminate).unwrap();

        self.thread.join().unwrap();
    }

    pub async fn ensure_keypair(&mut self) -> color_eyre::Result<(), Error> {
        let _guard = self.mutex.lock().await;

        self.tx.send(KeychainCommand::EnsureKeypair)?;

        let resp = self.rx.recv().await;

        match resp {
            Some(KeychainResponse::Ok) => Ok(()),
            Some(KeychainResponse::Err(err)) => Err(err),
            _ => Err(eyre!("Unexpected response")),
        }
    }

    pub async fn encrypt_data(&mut self, data: Vec<u8>) -> color_eyre::Result<Vec<u8>, Error> {
        let _guard = self.mutex.lock().await;

        self.tx.send(KeychainCommand::EncryptData(data))?;

        let resp = self.rx.recv().await;

        match resp {
            Some(KeychainResponse::OkWithData(data)) => Ok(data),
            Some(KeychainResponse::Err(err)) => Err(err),
            _ => Err(eyre!("Unexpected response")),
        }
    }

    pub async fn decrypt_data(
        &mut self,
        data: Vec<u8>,
    ) -> color_eyre::Result<Zeroizing<Vec<u8>>, Error> {
        let _guard = self.mutex.lock().await;

        self.tx.send(KeychainCommand::DecryptData(data))?;

        let resp = self.rx.recv().await;

        match resp {
            Some(KeychainResponse::OkWithData(data)) => Ok(Zeroizing::new(data)),
            Some(KeychainResponse::Err(err)) => Err(err),
            _ => Err(eyre!("Unexpected response")),
        }
    }
}
