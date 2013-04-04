<?php
function ft_decodercsv_info() {
  return array(
    'name' => 'Decoder: converte arquivos CSV para JSON',
  );
}

function ft_decodercsv_action($act) {
	global $ft;
	if ($act == 'decodercsv') {
		$nome = substr(trim(ft_stripslashes($_REQUEST["file"])), 0, -4);
		$fp = @fopen(ft_get_dir()."/$nome.json", "wb");
		if ($fp) {
			if (($handle = @fopen(ft_get_dir()."/$nome.csv", "r")) != FALSE) {
				$primeira = 0;
				while (($data = fgetcsv($handle, 4000, ";")) != FALSE) {
					$num = count($data);
					if ($primeira == 0) {
						$jsonstring = '{"registros":[[[';
					}
					else {
						$jsonstring .= ",[";
					}
					for ($j = 0; $j < $num; $j++) {
						if ($j == 0) {
							if ($data[$j] == "") {
								$jsonstring .= "null";
							}
							else {
								$jsonstring .= '"'.$data[$j].'"';
							}
						}
						else if ($j == 2) {
							$jsonstring .= ','.$data[$j];
						}
						else if ($j == 3 && $data[$j] != "") {
							$alternativas = explode(",", $data[$j]);
							$alt = 0;
							$jsonstring .= ",[";
							foreach ($alternativas as $k) {
								if ($alt == 0) {
									$jsonstring .= '"'.$k.'"';
								}
								else {
									$jsonstring .= ',"'.$k.'"';
								}
								$alt++;
							}
							$jsonstring .= "]";
						}
						else if ($j == 5) {
							if ($data[$j] == "") {
								$jsonstring .= ',0';
							}
							else {
								$jsonstring .= ',1';
							}
						}
						else {
							if ($data[$j] == '') {
								$jsonstring .= ',null';
							}
							else {
								$jsonstring .= ',"'.$data[$j].'"';
							}
						}
					}
					$jsonstring .= "]";
					$primeira++;
				}
				fclose($handle);
				
				$jsonstring .= ']]}';
				
				$jsonstring = utf8_encode($jsonstring);
				
				//echo $jsonstring;
			}

			fputs ($fp, $jsonstring);
			fclose($fp);
			ft_set_message("Arquivo convertido!");
		}
		ft_redirect("dir=".rawurlencode($_REQUEST['dir']));
	}
}

function ft_decodercsv_fileextras($file, $dir) {
  if (ft_get_ext($file) == 'csv' && !is_dir("{$dir}/{$file}")) {
		return 'decodercsv';
	}
  return FALSE;
}

function ft_decodercsv_add_js_call() {
  return 'ft.fileactions.decodercsv = {type: "sendoff", link: "Converter para JSON", text: "Você deseja converter esse arquivo?", button: "Sim!"};';
}

?>