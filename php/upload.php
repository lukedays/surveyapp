<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Upload</title>
</head>

<body>
<?php
	$target_path = 'arquivos/';
	$target_path = $target_path.basename($_FILES['arquivo']['name']); 
	move_uploaded_file($_FILES['arquivo']['tmp_name'], $target_path);
?>
</body>
</html>