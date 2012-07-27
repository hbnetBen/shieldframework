<?php

namespace Shield;

class Session extends Base
{
    /**
     * Path to save the sessions to
     * @var string
     */
    private $_savePathRoot  = '/tmp';

    /**
     * Save path of the saved path
     * @var string
     */
    private $_savePath      = '';

    /**
     * The MCrypt Cipher To Use For Encrypting Data
     * @var string
     */
    private $_cipher = MCRYPT_RIJNDAEL_256;

    /**
     * Key for storing the session data
     * This needs to be a strong cryptographic key
     * @var string
     */
    private $_encKey        = '';

    /**
     * Key for signing the encrypted session data
     * This needs to be a strong cryptographic key
     * @var string
     */
    private $_sigKey        = '';

    /**
     * Init the object, set up the session config handling
     * 
     * @return null
     */
    public function __construct($di)
    {
        session_set_save_handler(
            array($this, "open"),
            array($this, "close"),
            array($this, "read"),
            array($this, "write"),
            array($this, "destroy"),
            array($this, "gc")
        );

        $sessionKey = $di->get('Config')->get('session_key');
        if ($sessionKey !== null) {
            $this->_key = $sessionKey;
        }

        parent::__construct($di);
        $this->setEncryptionKey($this->_di->config->get('session.encryption_key'));
        $this->setSignatureKey($this->_di->config->get('session.signature_key'));
        $this->setCipher($this->_di->config->get('session.cipher') ?: $this->_cipher);
    }

    /**
     * Overwrite the key prior to destruction
     *
     * @return null
     */
    public function __destruct() {
        $this->_sigKey &= str_repeat(chr(0), strlen($this->_sigKey));
        $this->_encKey &= str_repeat(chr(0), strlen($this->_encKey));
    }


    /**
     * Write to the session
     * 
     * @param integer $id   Session ID
     * @param mixed   $data Data to write to the log
     * 
     * @return null
     */
    public function write($id,$data)
    {
        $this->checkKeys();
        $path = $this->_savePathRoot.'/shield_'.$id;
        $ivSize = mcrypt_get_iv_size($this->_cipher, MCRYPT_MODE_CFB);
        $iv = mcrypt_create_iv($ivSize, MCRYPT_DEV_URANDOM);

        $data = $this->pad($data);

        $cipherText = mcrypt_encrypt($this->_cipher, $this->_encKey, $data, MCRYPT_MODE_CFB, $iv);
        $hash = hash_hmac('sha512', $iv . $cipherText, $this->_sigKey, true);
        $data = $iv . $cipherText . $hash;

        file_put_contents($path,$data);
    }

    public function setCipher($cipher)
    {
        if (in_array($cipher, mcrypt_list_algorithms())) {
            $this->_cipher = $cipher;
        }
    }

    /**
     * Set the key for encrypting the data with
     * 
     * @param string $key Key string
     * 
     * @return null
     */
    public function setEncryptionKey($key)
    {
        $this->_encKey = $key;
    }

    /**
     * Set the key for signing the data with
     * 
     * @param string $key Key string
     * 
     * @return null
     */
    public function setSignatureKey($key)
    {
        $this->_sigKey = $key;
    }

    /**
     * Read in the session
     * 
     * @param string $id Session ID
     * 
     * @return null
     */
    public function read($id)
    {
        $this->checkKeys();
        $path = $this->_savePathRoot.'/shield_'.$id;

        if (is_file($path)) {
            $data = file_get_contents($path);
            $ivSize = mcrypt_get_iv_size($this->_cipher, MCRYPT_MODE_CFB);
            if (strlen($data) < $ivSize + 64 + 1) {
                return null;
            }
            $iv = substr($data, 0, $ivSize);
            $hash = substr($data, -64);
            $cipherText = substr($data, $ivSize, -64);

            // verify the hash first
            if ($hash !== hash_hmac('sha512', $iv . $cipherText, $this->_sigKey, true)) {
                return null;
            }

            $data = mcrypt_decrypt($this->_cipher, $this->_salt, $encKey, MCRYPT_MODE_CFB, $iv);
            $data = $this->stripPadding($data);
            if (!$data) {
                return null;
            }
        }

        return $data;
    }

    /**
     * Close the session
     * 
     * @return boolean Default return (true)
     */
    public function close()
    {
        return true;
    }

    /**
     * Perform garbage collection on the session
     * 
     * @param int $maxlifetime Lifetime in seconds
     * 
     * @return null
     */
    public function gc($maxlifetime)
    {
        $path = $this->_savePathRoot.'/shield_*';

        foreach (glob($path) as $file) {
            if (filemtime($file) + $maxlifetime < time() && file_exists($file)) {
                unlink($file);
            }
        }

        return true;
    }

    /**
     * Open the session
     * 
     * @param string $savePath  Path to save the session file locally
     * @param string $sessionId Session ID
     * 
     * @return null
     */
    public function open($savePath,$sessionId)
    {
        // open session
    }

    /**
     * Destroy the session
     * 
     * @param string $id Session ID
     * 
     * @return null
     */
    public function destroy($id)
    {
        $path = $this->_savePathRoot.'/shield_'.$id;
        if (is_file($path)) {
            unlink($path);
        }
        return true;
    }

    /**
     * Refresh the session with a new ID
     * 
     * @return null
     */
    public function refresh()
    {
        $sess = $this->_di->get('Input')->getAll('session');
        $id = session_regenerate_id(true);
        session_destroy();
        session_start();
        $_SESSION = $sess;
    }

    /**
     * Check the keys to determine if they were setup properly
     *
     * @return null
     * @throws RuntimeException when either key is invalid
     */
    private function checkKeys() {
        $valid = true;
        if (strlen($this->_encKey) !== mcrypt_get_key_size($this->_cipher)) {
            $valid = false;
        }
        if (strlen($this->_sigKey) < 64) {
            $valid = false;
        }
        if (!$valid) {
            throw new \RuntimeException("Keys were not setup properly prior to session start");
        }
    }

    private function pad($data) {
        $blockSize = mcrypt_get_block_size($this->_cipher, MCRYPT_MODE_CFB);
        $padSize = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($padSize), $padSize);
    }

    private function stripPadding($data) {
        $padSize = ord($data[strlen($data) - 1]);
        if ($padSize > strlen($data)) {
            return false;
        }
        $padBlock = str_repeat(chr($padSize), $padSize);
        if (substr($data, -1 * $padSize) !== $padSize) {
            // Invalid padding detected!
            return false;
        }
        return substr($data, 0, -1 * $padSize);
    }

}
