<?php
function ft_encoder_info() {
  return array(
    'name' => 'Encoder: converte arquivos JSON para CSV',
  );
}

function ft_encoder_action($act) {
	global $ft;
	if ($act == 'encoder') {
		if (substr(trim(ft_stripslashes($_REQUEST["file"])), -3) == 'xml') {
			$nome = substr(trim(ft_stripslashes($_REQUEST["file"])), 0, -4);
		}
		if (substr(trim(ft_stripslashes($_REQUEST["file"])), -3) == 'son') {
			$nome = substr(trim(ft_stripslashes($_REQUEST["file"])), 0, -5);
		}
		$fp = @fopen(ft_get_dir()."/$nome.csv", "wb");
		if ($fp) {
			$jsonstring = file_get_contents(ft_get_dir()."/$nome.json");
			
			$jsonobj = json_decode($jsonstring);
			
			$coluna = 0;
			foreach($jsonobj->{"registros"} as $i) {
				if ($coluna == 0) {
					$linha = 0;
					foreach($i as $j) {
						if ($linha == 0) {
							$csvstring = $j[0];
							$tipos[$linha] = $j[2];
						}
						else {
							$csvstring .= "\t";
							$csvstring .= $j[0];
							$tipos[$linha] = $j[2];
						}
						$linha++;
					}
				}
				else {
					$linha = 0;
					foreach ($i as $j) {
						if ($tipos[$linha] == 4) {
							if ($linha == 0) {
								$csvstring .= "\n";
								$vetor = 0;
								if ($j != "") {
									foreach ($j as $k) {
										if ($vetor == 0) { 
											$csvstring .= $k;
										}
										else {
											$csvstring .= "; ";
											$csvstring .= $k;
										}
										$vetor++;
									}
								}
								else {
									$csvstring .= $j;
								}
							}
							else {
								$csvstring .= "\t";
								$vetor = 0;
								if ($j != "") {
									foreach ($j as $k) {
										if ($vetor == 0) { 
											$csvstring .= $k;
										}
										else {
											$csvstring .= "; ";
											$csvstring .= $k;
										}
										$vetor++;
									}
								}
								else {
									$csvstring .= $j;
								}
							}
						}
						else if ($tipos[$linha] == 5) {
							if ($linha == 0) {
								$csvstring .= "\n";
								if ($j != "") {
									$csvstring .= $j[0]." / ".$j[1]." / ".$j[2];
								}
								else {
									$csvstring .= $j;
								}
							}
							else {
								$csvstring .= "\t";
								if ($j != "") {
									$csvstring .= $j[0]." / ".$j[1]." / ".$j[2];
								}
								else {
									$csvstring .= $j;
								}	
							}
						}
						else {
							if ($linha == 0) {
								$csvstring .= "\n";
								$csvstring .= $j;
							}
							else {
								$csvstring .= "\t";
								$csvstring .= $j;
							}
						}
						$linha++;
					}
				}
				$coluna++;
			}
			
			$csvstring = chr(255).chr(254).mb_convert_encoding($csvstring, 'UTF-16LE', 'UTF-8');
			fputs ($fp, $csvstring);
			fclose($fp);
			ft_set_message("Arquivo convertido!");
		}
		ft_redirect("dir=".rawurlencode($_REQUEST['dir']));
	}
}

function ft_encoder_fileextras($file, $dir) {
  if (ft_get_ext($file) == 'json' && !is_dir("{$dir}/{$file}")) {
		return 'encoder';
	}
  return FALSE;
}

function ft_encoder_add_js_call() {
  return 'ft.fileactions.encoder = {type: "sendoff", link: "Converter para CSV", text: "Você deseja converter esse arquivo?", button: "Sim!"};';
}

?>