<?php
/**
 * GPG - clase de cifrado y descifrado
 *
 * Uso:
 *
 * Con ruta de llave y texto
 * --------------------------
 * 
 * $gpg = new GPG();
 * $gpg->establecerLlave('ruta/a/mi/llave/foo.asc');
 * $cifrado = $gpg->cifrar('lorem ipsum dolorem asimet');
 * $descifrar = $gpg->descifrar($cifrado);
 * 
 *
 * Con contenido de llave y ruta
 * ------------------------------
 * $gpg = new GPG();
 * $gpg->establecerLlave('ruta/a/mi/llave/foo.asc');
 * $cifrado = $gpg->cifrar('ruta/a/mi/archivo/foobar.txt');
 * $descifrar = $gpg->descifrar($cifrado);
 */

/**
 * GPG - Clase de cifrado y descifrado en gpg
 *
 * @author Mauricio Beltran <mauricio.beltran@usolix.cl>
 * @license GPL v3.0 <http://www.gnu.org/licenses/gpl-3.0.txt>
 * @version 1.0.0
 */
class GPG
{
    /**
     * Recurso de el proceso gnupg
     * @var resource
     */
    private $recurso;
    /**
     * Llave gpg
     * @var string
     */
    private $llave='';

    /**
     * Constructor de la clase, establece el entorno e inicia el proceso gpg
     */
    public function __construct()
    {
        putenv("GNUPGHOME=/tmp");
        $this->recurso = gnupg_init();
    }

    /**
     * Cifra un mensaje o archivo en gpg
     * @param  mixed $contenido ruta del archivo o texto a cifrar
     * @return mixed            retorna el contenido encriptado o captura la excepcion
     */
    public function cifrar($contenido)
    {
        if (file_exists($contenido)) {
            $contenido = file_get_contents($contenido);
        }

        try {
            gnupg_addencryptkey($this->recurso, $this->obtenerHuella());
            return gnupg_encrypt($this->recurso, $contenido);
        } catch (\Exception $e) {
            return $e;
        }        
    }

    /**
     * Descrifra un texto encriptado
     * @param  string $cifrado    texto cifrado
     * @param  string $passphrase passphrase de la llave gpg
     * @return mixed             retorna el contenido desencriptado o captura la excepcion
     */
    public function descrifrar($cifrado, $passphrase='')
    {
        try {
            gnupg_adddecryptkey($this->recurso, $this->obtenerHuella(), $passphrase);
            return gnupg_decrypt($this->recurso, $cifrado);  
        } catch (\Exception $e) {
            return $e;
        }        
    }

    /**
     * Establece una nueva llave
     * @param  string $llave Puede ser el contenido de la llave o la ruta en la que se encuentra esta
     * @return void
     */
    public function establecerLlave($llave)
    {
        if (file_exists($llave)) {
            $llave = file_get_contents($llave);
        }

        $this->llave = $llave;
    }

    /**
     * Obtiene la llave almacenada
     * @return mixed Retorna la llave almacenada o dispara un error en caso de que no se encuentre establecida
     */
    public function obtenerLlave()
    {
        if (trim($this->llave)=='') {
            throw new \Exception("Por favor, establezca la llave primero", 1);            
        }

        return $this->llave;
    }

    /**
     * Obtiene la huella (Fingerprint) de una clave gpg
     * @return string huella obtenida
     */
    private function obtenerHuella()
    {
        $datos_llave = gnupg_import($this->recurso, $this->obtenerLlave());
        return $datos_llave['fingerprint'];
    }    
}