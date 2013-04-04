<?php
function ft_decoder_info() {
  return array(
    'name' => 'Decoder: converte arquivos XML para JSON',
  );
}

function ft_decoder_action($act) {
	global $ft;
	if ($act == 'decoder') {
		$nome = substr(trim(ft_stripslashes($_REQUEST["file"])), 0, -4);
		$fp = @fopen(ft_get_dir()."/$nome.json", "wb");
		if ($fp) {
			$xmlobj = simplexml_load_file(ft_get_dir()."/$nome.xml");
			$xmlobj->registerXPathNamespace('h', 'http://www.w3.org/1999/xhtml');
			
			$numeroDeVariaveis = 0;
			foreach ($xmlobj->xpath('h:head') as $interadorHead) {	
				foreach ($interadorHead->model->bind as $interadorBind) {
					$numeroDeVariaveis++;
				}
			}
			
			for ($linha = 0; $linha < $numeroDeVariaveis; $linha++) {
				for ($coluna = 0; $coluna < 6; $coluna++) {
					if ($coluna != 3) {
						$variavel[$linha][$coluna] = 'null';
					}
				}
			}
			
			$linha = 0;
			foreach ($xmlobj->xpath('h:head') as $interadorHead) {
				foreach ($interadorHead->model->bind as $interadorBind) {
					$variavel[$linha][0] = substr($interadorBind['nodeset'], 6);
					if ($interadorBind['type'] == 'string') {
						$variavel[$linha][2] = 1;
					} else if ($interadorBind['type'] == 'int') {
						$variavel[$linha][2] = 3;
					} else if ($interadorBind['type'] == 'date') {
						$variavel[$linha][2] = 5;
					}
					if ($interadorBind['relevant']) {
						$expressaoLogica = $interadorBind['relevant'];
						$expressaoLogica = ltrim($expressaoLogica, '(');
						$expressaoLogica = rtrim($expressaoLogica, ')');
						$variavel[$linha][4] = $expressaoLogica;
					}
					if ($interadorBind['required']) {
						$variavel[$linha][5] = 1;
					}
					$linha++;
				}
			}
			
			$linha = 0;
			foreach ($xmlobj->xpath('h:body') as $interadorBody) {
				for ($linha = 0; $linha < $numeroDeVariaveis; $linha++) {
					foreach ($interadorBody->select1 as $interadorSelect1) {
						if ('/data/'.$variavel[$linha][0] == $interadorSelect1['ref']) {
							$numeroDeOpcoes = 0;
							$variavel[$linha][2] = 6;
							
							foreach ($interadorSelect1->item as $interadorItem) {
								$numeroDeOpcoes++;
							}
							
							for ($numeroDoCampo = 0; $numeroDoCampo < $numeroDeOpcoes; $numeroDoCampo++) {
								foreach ($xmlobj->xpath('h:head') as $interadorHead) {
									foreach ($interadorHead->model->itext->translation->text as $interadorText) {
										if ($interadorText['id'] == '/data/'.$variavel[$linha][0].':option'.$numeroDoCampo) {
											$variavel[$linha][3][$numeroDoCampo] = '"'.$interadorText->value.'"';
										}
									}
								}
							}
						}
					}
				}
				
				foreach ($interadorBody->select as $interadorSelect) {
					for ($linha = 0; $linha < $numeroDeVariaveis; $linha++) {
						if ('/data/'.$variavel[$linha][0] == $interadorSelect['ref']) {
							$numeroDeOpcoes = 0;
							$variavel[$linha][2] = 4;
							
							foreach ($interadorSelect->item as $interadorItem) {
								$numeroDeOpcoes++;
							}
			
							for ($numeroDoCampo = 0; $numeroDoCampo < $numeroDeOpcoes; $numeroDoCampo++) {
								foreach ($xmlobj->xpath('h:head') as $interadorHead) {
									foreach ($interadorHead->model->itext->translation->text as $interadorText) {
										if ($interadorText['id'] == '/data/'.$variavel[$linha][0].':option'.$numeroDoCampo) {
											$variavel[$linha][3][$numeroDoCampo] = '"'.$interadorText->value.'"';
										}
									}
								}
							}
						}
					}
				}
			}
			
			for ($linha = 0; $linha < $numeroDeVariaveis; $linha ++) {
				if ($variavel[$linha][2] != 4 && $variavel[$linha][2] != 6) {
					$variavel[$linha][3] = 'null';
				}
			}
			
			$linha = 0;
			foreach ($xmlobj->xpath('h:head') as $interadorHead) {
				for ($linha = 0; $linha < $numeroDeVariaveis; $linha++) {
				$adicionarQuebraDeLinha = false;
					foreach ($interadorHead->model->itext->translation->text as $interadorText) {
						if ('/data/'.$variavel[$linha][0].':label' == $interadorText['id'] && $interadorText->value != '') {
							$variavel[$linha][1] = $interadorText->value;
							$adicionarQuebraDeLinha = true;
						}
						if ('/data/'.$variavel[$linha][0].':hint' == $interadorText['id'] && $interadorText->value != '') {
							if ($adicionarQuebraDeLinha) {
								$variavel[$linha][1] .= '\n'.$interadorText->value;
							} else {
								$variavel[$linha][1] = $interadorText->value;
							}
						}
					}
				}
			}
			
			$jsonstring = '{"registros":[[';
			$primeiraQuestao = true;
			foreach ($variavel as $interadorDeVariavel) {
				if ($primeiraQuestao) {
					$jsonstring .= '[';
					$primeiraQuestao = false;
				} else {
					$jsonstring .= ',[';
				}
				if ($interadorDeVariavel[0]) $jsonstring .= '"'.$interadorDeVariavel[0].'"';
				$jsonstring .= ',';
				if ($interadorDeVariavel[1]) $jsonstring .= '"'.$interadorDeVariavel[1].'"';
				$jsonstring .= ',';
				if ($interadorDeVariavel[2]) $jsonstring .= $interadorDeVariavel[2];
				$jsonstring .= ',';
				if ($interadorDeVariavel[2] == 4 || $interadorDeVariavel[2] == 6) {
					$jsonstring .= '[';
					$cont = 0;
					foreach ($interadorDeVariavel[3] as $vetorDeOpcoes) {
						if ($cont == 0) {
							$jsonstring .= $vetorDeOpcoes;
						} else {
							$jsonstring .= ','.$vetorDeOpcoes;
						}
						$cont++;
					}
					$jsonstring .= '],';
				} else {
					$jsonstring .= 'null'.',';
				}
				if ($interadorDeVariavel[4] != 'null') {
					$jsonstring .= '"'.$interadorDeVariavel[4].'",';
				} else {
					$jsonstring .= 'null'.',';
				}
				if ($interadorDeVariavel[5]) $jsonstring .= $interadorDeVariavel[5]; //Requerida?
				$jsonstring .= ']';
			}
			$jsonstring .= ']]}';
			
			fputs ($fp, $jsonstring);
			fclose($fp);
			ft_set_message("Arquivo convertido!");
		}
		ft_redirect("dir=".rawurlencode($_REQUEST['dir']));
	}
}

function ft_decoder_fileextras($file, $dir) {
  if (ft_get_ext($file) == 'xml' && !is_dir("{$dir}/{$file}")) {
		return 'decoder';
	}
  return FALSE;
}

function ft_decoder_add_js_call() {
  return 'ft.fileactions.decoder = {type: "sendoff", link: "Converter para JSON", text: "Você deseja converter esse arquivo?", button: "Sim!"};';
}

?>