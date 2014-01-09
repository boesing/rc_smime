<?php
/**
 * Verify, sign, decrypt, encrypt S/Mime messages
 *
 * This plugin will verify a message received with s/mime attachment.
 * 
 * @author Max Boesing <max@kriegt.es>
 * @since 20140109 11:42
 */

/**
 * class smime
 *
 * @author Max Boesing <max@kriegt.es>
 * @since 20140109 11:42
 */
class smime extends rcube_plugin 
{
    /**
     * Flag if the viewed message is signed
     * @var boolean
     */
    protected   $bMessageIsSigned   = false;

    /**
     * Flag if the viewed message signature is valid
     * @var boolean
     */
    protected   $bMessageIsValid    = false;

	/**
	 * Initialize plugin functionality 
	 *
	 * @return void
	 * @author Max Boesing <max@kriegt.es>
	 * @since 20140109 11:42
	 */
    public function init()
    {
        if( !extension_loaded('openssl') ) {
            trigger_error( "OpenSSL extension is required for smime extension!", E_USER_WARNING );
            return;
        }

        $this->load_config('config.inc.php');

        $this->add_hook('message_load', array( $this, 'verify' ));
        $this->add_hook('message_headers_output', array( $this, 'message_headers_output' ));
    }

	/**
	 * Verifies given data
	 *
	 * @param string[]
	 * @return void
	 * @author Max Boesing <max@kriegt.es>
	 * @since 20140109 11:42
	 */
    public function verify( $args )
    {
        $oRcubeMessage = $args['object'];
        $sHeader = $oRcubeMessage->get_header('Content-Type', false);
        # Check for Content-Type
        if( strtolower($sHeader) != 'multipart/signed' ) {
            return;
        }
        # The message is signed
        $this->bMessageIsSigned = true;

        # Check for mimetype
        $oRcubeMessagePart = $oRcubeMessage->headers->structure;
        if(! $oRcubeMessagePart instanceOf rcube_message_part ) {
            return;
        }
        
        $bValidMimeTypeFound = false;
        foreach( $oRcubeMessagePart->parts AS $oRcubeMimeMessagePart ) {
            if( $oRcubeMimeMessagePart->mimetype == 'application/pkcs7-signature' ) {
                $bValidMimeTypeFound = true;
                break;
            }
        }

        # If no pkcs7 mimetype found, we dont need to check this message for 
        # validity
        if( !$bValidMimeTypeFound ) {
            return;
        }

        $iUid = $oRcubeMessage->uid;
        $oApp = rcube::get_instance();
        $sSSLCertificatesPaths = $oApp->config->get('ssl_certificate_paths');
        $oStorage = $oApp->get_storage();

        # Create a temporary file to store the raw mail
        $sBodyTempnam = tempnam( sys_get_temp_dir(), 'rcube' );

        # Open the file because we need a filehandle to store the raw body
        $rRawBodyFile = fopen( $sBodyTempnam, 'w' );
        $oStorage->get_raw_body( $iUid, $rRawBodyFile );
        fclose($rRawBodyFile);

        # Check with openssl if the message is signed correctly
        $this->bMessageIsValid = openssl_pkcs7_verify( $sBodyTempnam, PKCS7_TEXT, '/dev/null', $sSSLCertificatesPaths );
        unlink( $sBodyTempnam );
    }
    
	/**
     * Manipulates the headers table if the current message
     * is a s/mime message
	 *
	 * @param string[]
	 * @return string[]
	 * @author Max Boesing <max@kriegt.es>
	 * @since 20140109 14:16
	 */
    public function message_headers_output( $args ) 
    {
        if( !$this->bMessageIsSigned ) {
            return $args;
        }

        $aOutput = $args['output'];
        $sIconVerificationOkay = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACP0lEQVQ4T6WTW0hTcRzHv1ttc56zKTYSnEY4IiiDXkZFO10YFElqPcwIL09JBdVAWWgPuR7CGgiroKgHoYcQXGDUS3cqNB9ybBGLYmE7WjLZ5XTc1XPZaR5hbGjR6Pf2v3w+f378vn8F/rMU5fLOMVtNAGA97R5xmS1LMPjAdq5Crb3FCVlIvGR1dnte/7Pg0v1WO6HRu5vNHWDTMbzyj4MX+CMFgc25Xe1xBri1Wuq712wnNaS7ZU8nFtMhaFQkOF6FZ9NjKy2cv2m9rFq3/govCoPhePhasejCDaudqNS5W/d2IZYIYolPyW8kUhz8QR8UZ1yW/toa41AL1QXvl3fwfZ18LCF35+7FqaenXRY7qdW52/Z1Y4H9jCyXlOEoE0OQ/g5BkChFz9XdUvvhHsxF/TAatiGTEfD8/UNkl5IDJFE91HawGz+iH5HhEjIcYxjM0LOQBJEacXonFCcHdvRXVemGGhvroVQqYdA3oH5DEyZ9L2BuohCKeJFeWpThOMOCpn8ix4vU6PXARGGMx/u2uPQk4dhsqpMlFWoSW+t34dv8NFJZVoZ/MQnM0WGIEk+ND8/IcEkOjp7d5CL1WkeDqVaWFBfLJDFPRyDlJOrJ7dkCvCpIh05tdBE6wmFsNEChXJlwgkkhTMchiAL1ciRSAq+ZxP2d1cOkvrK3zlSDJJvFQojJ95yj3owyq+A1BcublhO6YQ2h7uUyfH5UuQNTnuTbkp6KFn+MsvmYaueHR/yn/F3505Qt+BtUfPYbUlHqzfAnX9IAAAAASUVORK5CYII=';
        $sIconVerificationFailed = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACnUlEQVQ4T22TyU8TYRjGn2mBIpTuFdtQDQgqAnHBuBBSJCRC0Gg0HjSe9OKSaUo86V+gF03rTMST4WJUNBoSgks8KIukRGPdoKISFYVClxkLJSw64zczzLDId5r5nvf5vdsMhWXnsdNQ3BCb+bL8XnpfSaPUwFZAb3TmXslxrfZPjY4HG2PppsWQDmduYCVNA7Q7jNc99d6zRYfrMNDyELHQm+D+eUi7M4dx1eyhNxxrxOCdDow+DzUfiE+ekxLIgDankfHUVdNFtZsxGwkhq9yLyIMujPWFg0TWu7276JL6SswO9MBQVo3BR68w0hliD8UmfVQr6dmc7/5ceeYgZvtfKlXrdDBU1CDS1gN9ViYk88yHbkAUZNlQ4UXftXuYiMbWyRXcJxXYC0x00bZ8UGpTBJK9tRYQ/mL6badmFkXg6+sxJEdS7FGpAnVQt50mxuEy0oUV9iUQEIOaWTa/iyMZTbPHYymfNgMVcstuYmxrcujCTdYFyLwomYf6OXDjU+yJhGL+D9BCAK6y9bTbnCbTVfpVj0hufiZXIRr5FjyZSGkr1lq4aTUx7h1b6JKqUqR6n2lla5l0euRV7cOnF2FEwx+Dp5IKRAbcsFkCBdvL/Rt3l4LvfkIGp2SXypaD5tNQBGKubkCk5z1Gwv3saY73UYzZXGhyWod2HqkF37XITIzfo3PQEbcnP0PJJMEIxLq3Eb13n+I3N66skSEV2I16f4GDkgOlxMNxAckJgZV0W56O9jh0GmQ4ISCRElifVIHaY8BqYWy5JNAiYpinkEwLbBMJkHRZMyraLx6IT6K5ieMWPmUVctViCRgyKP/MHzF4nueX/ExEY7IzKXp6TmSJtvIaJdBlq3XtBY77oe1v0cMlk6n4Yiq15Ff/ByGcCctPbC34AAAAAElFTkSuQmCC';
        
        $aSMimeHeader = array(
            'title' => 'S/Mime',
            'value' => sprintf('<img src="%s" alt="%s" />', $this->bMessageIsValid ? $sIconVerificationOkay : $sIconVerificationFailed, $this->bMessageIsValid ? 'validated' : 'invalid'),
#            'raw'   => '',
            'html'  => true,
        );

        $aOutput += array(
            'smime' => $aSMimeHeader
        );

        $args['output'] = $aOutput;
        return $args;
    }
}

/**
 *  vim: set expandtab tabstop=4 softtabstop=4 shiftwidth=4 textwidth=80 foldmethod=marker:
 */
