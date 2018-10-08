<?php

	include 'xmlseclibs-master/xmlseclibs.php';
	use XMLSecLibs\XMLSecurityDSig;
	use XMLSecLibs\XMLSecurityKey;	

	/** 
	 * Classe desenvolvida para comunica��o com servi�o NFSe WebIss ou outro
	 * Para outros servi�os � essencial o uso definir no construtor o endere�o do servi�o que n�o seja webiss
	 * Por padr�o usei o endere�o de homologa��o do webiss
	 * 
	 * @author Carlos Alberto <karloswebmaster@gmail.com>
	 * @version 0.1 
	 * @copyright  GPL � 2006, genilhu ltda. 
	 * @access public
	 * @package xmlseclibs-master 
	 * @subpackage src
	 * @example Classe NFSeWSDL. 
	 */ 
	class NFSeWSDL
	{
		//Url Padr�o do servi�o SOA abrasf -> pode ser passado como parâmetro no construtor outro servi�o
		const URL_HOMOLOGACAO	= 'https://homologacao.webiss.com.br/ws/nfse.asmx';
		const URL_PRODUCAO		= 'https://simoesfilhoba.webiss.com.br/ws/nfse.asmx';		

		//Cabe�alho padr�o do servi�o soa, poder� ser definido no construtor outro cabe�alho que se adeque a outro tipo de servi�o.
		const DEFAULT_HEADER	= '<?xml version="1.0" encoding="UTF-8"?><cabecalho xmlns="http://www.abrasf.org.br/nfse.xsd" versao="2.02"><versaoDados>2.02</versaoDados></cabecalho>';

		public $debug = false;
		
		//Vari�vel para definir se o ambiente utilizado � de produ��o ou homologacao
		private $a_producao = false;
		private $urlService;
		private $defaultHeader;
		
		private $passwd;
		private $srcXml;		
		
		private $pathCertificates;
		private $cnpj;
		private $inscricaoMunicipal;

		private $publicKey     = 'publicKey.pem'; 
		private $privateKey    = 'privateKey.pem';
		private $all_cert      = 'all_cert.pem';
		private $srcPfx;

		private $messages = array();
		/**
		 * Construtor gera os arquivos publicos e privados para assinar os lotes, sendo que o nome do arquivo pfx deve ser o cnpj da empresa
		 * @param $cnpj string contendo o cpf ou cnpj, sendo que o certificado PFX deve estar no diret�rio com o nome igual ao CNPJ
		 * @param $passwd string contendo a senha do certificado digital
		 * @param $pathCertificates string contendo o caminho do retet�rio onde est� os certificados digitais
		 * @param $productionEnvironment define o ambiente de trabalho se � produ��o ou homologa��o. Verificar constantes de URL_HOMOLOGACAO E URL_PRODUCAO
		 * @param $loadCert vari�vel que � definido para extratir as chaves p�blicas e privadas no diret�rio definido no $pathCertificates
		 * @param $defaultHeader define o cabe�alho padr�o para envio das mensagens ao WebService.
		 */
		public function __construct($cnpj, $passwd, $pathCertificates, $productionEnvironment=false, $loadCert = true, $defaultHeader = NFSeWSDL::DEFAULT_HEADER)
		{
			if( !$productionEnvironment )
				$this -> urlService 	= $urlService = NFSeWSDL::URL_HOMOLOGACAO;
			else
				$this -> urlService 	= $urlService = NFSeWSDL::URL_PRODUCAO;

			$this -> cnpj 				= $cnpj;
			$this -> defaultHeader 		= $defaultHeader;			
			$this -> passwd 			= $passwd;						
			$this -> pathCertificates 	= $pathCertificates;

			$this -> pfx 				= "{$this -> pathCertificates}/{$cnpj}.pfx";
			$this -> publicKey     		= "{$this -> pathCertificates}/{$this -> publicKey}"; 
			$this -> privateKey    		= "{$this -> pathCertificates}/{$this -> privateKey}";
			$this -> all_cert      		= "{$this -> pathCertificates}/{$this -> all_cert}";
			if($loadCert)
				$this->loadCert();
		}
		
		public function getUrlService()
		{
			return $this -> urlService;
		}

		public function setInscricaoMunicipal( $inscricao )
		{
			$this -> inscricaoMunicipal = $inscricao;
		}

		public function setXml( $srcXml )
		{
			$this -> srcXml = $srcXml;
		}
		/**
		 * @author <karloswebmaster@gmail.com>
		 * @param $srcXml string caminho do arquivo xml do lote a ser processado.
		 * @return processResult() Desolve um vetor contendo a lista de mensagens ou o protocolo e data de processamento do lote enviado.
		 */
		public function sendLoteRps()
		{			
			if(!isset( $this -> srcXml ))
				die("Defina o xml a ser enviado no lote de RPS");


			$xmlAssinado 	= $this -> assignXML( $this -> srcXml );
			$options = [
							'local_cert' 	=> $this -> all_cert		,
							'passphrase' 	=> $this -> passwd			,
							'trace'      	=> true      				, 
							'exceptions' 	=> true      				,
							'wsdl_cache' 	=> WSDL_CACHE_NONE 			,							
							'soap_version'	=> SOAP_1_1					,
							'encoding' 		=> 'UTF-8'					,
							'Location' 		=> $this -> urlService.'?op=RecepcionarLoteRps'
						];			
		   try
		   {
				$client = new SoapClient($this -> urlService.'?WSDL', $options);
				$function = 'RecepcionarLoteRps';
				$arguments= ['RecepcionarLoteRps' => [                                            
														'nfseCabecMsg' => $this -> defaultHeader,
														'nfseDadosMsg' => $xmlAssinado
													 ]
								];
				$options = [];
				$result = $client->__soapCall($function, $arguments, $options);

				$this -> printDebug( $client );

				return $this -> processResult( $result );
				
		   }
		   catch(Exception $e)
		   {
				throw new Exception("Falha ao RecepcionarLoteRps {$e -> getMessage()}", 1);
		   }		   
		}

		public function consultarLoteRPS( $nroProtocolo )
		{
			if(!isset($this -> inscricaoMunicipal))						
				die("Informe a inscricao municipal do CNPJ: {$this -> cnpj}, use o metodo setInscricaoMunicipal para o objeto atual");
			//XMl de consulta do lote
			$xml = '<?xml version="1.0" encoding="utf-8"?>                                                                                                                          
					<ConsultarLoteRpsEnvio xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.abrasf.org.br/nfse.xsd">
						<Prestador>
							<CpfCnpj>
								<Cnpj>'. $this -> cnpj .'</Cnpj>								
							</CpfCnpj>
							<InscricaoMunicipal>'. $this -> inscricaoMunicipal .'</InscricaoMunicipal>
						</Prestador>
						<Protocolo>'. $nroProtocolo .'</Protocolo>
					</ConsultarLoteRpsEnvio>';

			try
			{
				$options =	[
								'local_cert' 	=> $this -> all_cert		,
								'passphrase' 	=> $this -> passwd			,
								'trace'      	=> true      				, 
								'exceptions' 	=> true      				,
								'wsdl_cache' 	=> WSDL_CACHE_NONE 			,							
								'soap_version'	=> SOAP_1_1					,
								'encoding' 		=> 'UTF-8'					,
								'Location' 		=> $this -> urlService.'?op=ConsultarLoteRps'
							];

				$client = new SoapClient("{$this -> urlService}?WSDL", $options);
				$function = 'ConsultarLoteRps';
				$arguments= ['ConsultarLoteRps' => [                                            
														'nfseCabecMsg' => $this -> defaultHeader,
														'nfseDadosMsg' => $xml
													]
							];
				$options = [];
				  
				// print_r( $client -> __getFunctions() ); exit;
				$result = $client->__soapCall($function, $arguments, $options);
				return $this -> processResult( $result );
				
			}
			catch(Exception $e)
			{
				throw new Exception("Falha ao ConsultarLoteRps {$e -> getMessage()} {$e -> getLine()}", 1);
			}
		}

		public function getXmlAssign()
		{
			if(!isset( $this -> srcXml ))
				die("Defina o xml a ser assinado!");

			return $this -> assignXML( $this -> srcXml );
		}
		
		//Funcao para pegar a chave publica
		//Abre o certificado digital
		public function getPublicKey()
		{			
			$fp = fopen($this -> srcCertificate, "r");
			$pub_key = fread($fp, 8192);
			fclose($fp);
			//Pega a refer�ncia para a cheve p�blica
			$pub = openssl_get_publickey($pub_key);
			//Pega a chave p�blica (retorna um array)
			$keyData = openssl_pkey_get_details($pub);
			//Retorna a chave
			return $keyData['key'];
		}

		private function assignXML( $srcXml )
		{			
			$doc = new DOMDocument();
			$doc -> load( $srcXml );

			##### ASSINATURA DOS RPS INDIVIDUAIS	
			$itensInfDeclaracao = $doc -> getElementsByTagName( 'InfDeclaracaoPrestacaoServico' );			
			foreach($itensInfDeclaracao as $item)
			{						
				$idInfDecalaracao = $item -> getAttribute('Id');

				$objDSig = new XMLSecurityDSig('');	
				$objDSig -> setCanonicalMethod( XMLSecurityDSig::EXC_C14N );
				$transforms = 	[	
									'http://www.w3.org/2000/09/xmldsig#enveloped-signature', 
									'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
							    ];

				$objDSig -> addReference(
											$item 					, 
											XMLSecurityDSig::SHA1	,
											$transforms				,
											[ 
												'node_id' =>  $idInfDecalaracao
											]
										);
		
				$objKey = new XMLSecurityKey( XMLSecurityKey::RSA_SHA1, ['type' => 'private'] );
				$objKey -> loadKey($this -> privateKey, true);	
				$objDSig -> sign( $objKey );
					
				$objDSig -> add509Cert( file_get_contents( $this -> publicKey ) );
				$objDSig -> appendSignature( $item -> parentNode);
						
			}		
			##### FIM ASSINATURA DOS RPS

			

			////--- ASSINAR LOTERPS -> ASSINATURA DO LOTE INTEIRO	
			//Obt�m o id do Lote para associar assinatura
			$IdLoteRps   = $doc -> getElementsByTagName('LoteRps') -> item(0) -> getAttribute('Id');
			
			//Biblioteca de terceiros para assinatura de documentos
			$objDSig = new XMLSecurityDSig('');	
			$objDSig->setCanonicalMethod( XMLSecurityDSig::EXC_C14N );
			
			$transforms = 	[	
								'http://www.w3.org/2000/09/xmldsig#enveloped-signature', 
								'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
							];
			$objDSig->addReference(
									//$doc					,
									$doc -> getElementsByTagName('LoteRps') -> item(0),
									XMLSecurityDSig::SHA1	,
									$transforms				,
									[ 
										'node_id' => $IdLoteRps
									]
								);

			$objKey = new XMLSecurityKey( XMLSecurityKey::RSA_SHA1, array('type'=>'private') );
			$objKey->loadKey($this -> privateKey, true);	
			$objDSig->sign( $objKey );
			
			$objDSig->add509Cert(file_get_contents( $this -> publicKey ));
			$objDSig->appendSignature( $doc -> getElementsByTagName('LoteRps') -> item(0) -> parentNode );
			return $doc->saveXML();
		}	

		/** 
		 * @author <karloswebmaster@gmail.com>
		 * @return mensagem de retorno em um array 
		*/
		private function processResult( $result )
		{	
			$xml 	= simplexml_load_string( $result -> outputXML );
			$json 	= json_encode( $xml );
			return json_decode($json, true);
		}

		private function printDebug(SoapClient $client )
		{
			if($this -> debug)
			{
				$msg   = array();
				$msg[] = "<b>TIPOS DE DADOS DISPON�VEIS NO WEBSERVICE:</b> <br /><br />".  implode( ",<br />", $client -> __getTypes() );
				$msg[] = "<b>FUN��OES DISPON�VEIS NO WEBSERVICE:</b><br />". implode(", <br />", $client -> __getFunctions());
				$msg[] = "<b>ULTIMO CABE�ALHO ENVIADO:</b><br /><br />". $client -> __getLastRequestHeaders();
				$msg[] = "<b>ULTIMO CABE�ALHO RECEBIDO:</b><br /><br />". $client -> __getLastResponseHeaders();
				$msg[] = "<b>ULTIMO PACOTE ENVIADO:</b><br /><br />". $client -> __getLastRequest();
				$msg[] = "<b>ULTIMO PACOTE RECEBIDO:</b><br /><br />". $client -> __getLastResponse();

				echo "<pre>".implode("<hr>", $msg)."</pre>";
			}			
		}

		/**
		 * Gera��o das chaves privadas e p�blicas para utiliza��o nas rotinas, este ser� de forma autom�tica.
		 */
		private function loadCert()
		{			
			$x509CertData = array();			
			if ( ! openssl_pkcs12_read( file_get_contents( "{$this -> pfx}" ), $x509CertData, $this -> passwd ) )
			{
			  die('Certificado n�o pode ser lido. Verifique se a senha est� correta. � poss�vel que o arquivo esteja corrompido ou em formato invalido.');
	
			  return false;
			}
	
			$this->X509Certificate = preg_replace( "/[\n]/", '', preg_replace( '/\-\-\-\-\-[A-Z]+ CERTIFICATE\-\-\-\-\-/', '', $x509CertData['cert'] ) );
	
			if ( ! self::validateCert( $x509CertData['cert'] ) ) {
				return false;
			}

			if ( ! is_dir( $this -> pathCertificates ) ) {
			  if ( ! mkdir( $this -> pathCertificates, 0777 ) ) {
				die(' Falha ao criar o diretorio '.$this -> pathCertificates);
				return false;
			  }
			}
	
			if ( ! file_exists( $this->privateKey ) ) {
			  if ( ! file_put_contents( $this->privateKey, $x509CertData['pkey'] ) ) {
				die(' Falha ao criar o arquivo '.$this->privateKey);
				return false;
			  }
			}
	
			if ( ! file_exists( $this->publicKey ) ) {
			  if ( ! file_put_contents( $this->publicKey, $x509CertData['cert'] ) ) {
				die(' Falha ao criar o arquivo '.$this->publicKey);
				return false;
			  }
			}
	
			if ( ! file_exists( $this->all_cert ) ) {
			  if ( ! file_put_contents( $this->all_cert, $x509CertData['cert'] . $x509CertData['pkey'] ) ) {
				die(' Falha ao criar o arquivo '.$this->all_cert );
				return false;
			  }
			}
	
			return true;
		}

		//fun��o respons�vel pela valida��o do certificado
		public function validateCert( $cert ){
        
			$data = openssl_x509_read( $cert );
			$certData = openssl_x509_parse( $data );
	
			$certValidDate = gmmktime( 0, 0, 0, substr( $certData['validTo'], 2, 2 ), substr( $certData['validTo'], 4, 2 ), substr( $certData['validTo'], 0, 2 ) );
	
			// obtem o timestamp da data de hoje
			$dHoje = gmmktime(0,0,0,date("m"),date("d"),date("Y"));
	
			if ( $certValidDate < time() ){
			  die(' Certificado expirado em ' . date( 'Y-m-d', $certValidDate ) );
			  return false;
			}
	
			//diferen�a em segundos entre os timestamp
			$diferenca = $certValidDate - $dHoje;
	
			// convertendo para dias
			$diferenca = round($diferenca /(60*60*24),0);
			//carregando a propriedade
			$this->certDaysToExpire = $diferenca;
	
			return true;
		}
	}