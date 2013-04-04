<?php
/**
 * @file
 * File Thingie - Andreas Haugstrup Pedersen <andreas@solitude.dk>
 * The newest version of File Thingie can be found at <http://www.solitude.dk/filethingie/>
 * Comments, suggestions etc. are welcome and encouraged at the above e-mail.
 *
 * LICENSE INFORMATION FOR FILE THINGIE:
 * File Thingie is Copyright (c) 2003-2010 Andreas Haugstrup Pedersen. All Rights Reserved.
 *
 * File Thingie is free for non-commercial use. Commercial use costs $20 per copy of File Thingie.
 * Read more at: http://www.solitude.dk/filethingie/download
 * Contact <andreas@solitude.dk> for bulk discounts.
 */

# Version information #
define("VERSION", "2.5.7"); // Current version of File Thingie.
define("INSTALL", "SIMPLE"); // Type of File Thingie installation. EXPANDED or SIMPLE.
define("MUTEX", $_SERVER['PHP_SELF']);
$ft = array();
$ft['settings'] = array();
$ft['groups'] = array();
$ft['users'] = array();
$ft['plugins'] = array();

# Settings - Change as appropriate. See online documentation for explanations. #
define("USERNAME", "iphone"); // Your default username.
define("PASSWORD", "senha"); // Your default password.

$ft["settings"]["DIR"]               = "."; // Your default directory. Do NOT include a trailing slash!
$ft["settings"]["LANG"]              = "pt-br"; // Language. Do not change unless you have downloaded language file.
$ft["settings"]["MAXSIZE"]           = 2000000; // Maximum file upload size - in bytes.
$ft["settings"]["PERMISSION"]        = 0644; // Permission for uploaded files.
$ft["settings"]["DIRPERMISSION"]     = 0777; // Permission for newly created folders.
$ft["settings"]["LOGIN"]             = TRUE; // Set to FALSE if you want to disable password protection.
$ft["settings"]["UPLOAD"]            = TRUE; // Set to FALSE if you want to disable file uploads.
$ft["settings"]["CREATE"]            = TRUE; // Set to FALSE if you want to disable file/folder/url creation.
$ft["settings"]["FILEACTIONS"]       = TRUE; // Set to FALSE if you want to disable file actions (rename, move, delete, edit, duplicate).
$ft["settings"]["HIDEFILEPATHS"]     = FALSE; // Set to TRUE to pass downloads through File Thingie.
$ft["settings"]["DELETEFOLDERS"]     = FALSE; // Set to TRUE to allow deletion of non-empty folders.
$ft["settings"]["SHOWDATES"]         = FALSE; // Set to a date format to display last modified date (e.g. 'Y-m-d'). See http://dk2.php.net/manual/en/function.date.php 
$ft["settings"]["FILEBLACKLIST"]     = "ft2.php filethingie.js ft.css ft_config.php index.php"; // Specific files that will not be shown.
$ft["settings"]["FOLDERBLACKLIST"]   = "ft_plugins"; // Specifies folders that will not be shown. No starting or trailing slashes!
$ft["settings"]["FILETYPEBLACKLIST"] = "php phtml php3 php4 php5"; // File types that are not allowed for upload.
$ft["settings"]["FILETYPEWHITELIST"] = ""; // Add file types here to *only* allow those types to be uploaded.
$ft["settings"]["ADVANCEDACTIONS"]   = FALSE; // Set to TRUE to enable advanced actions like chmod and symlinks.
$ft["settings"]["LIMIT"]             = 0; // Restrict total dir file usage to this amount of bytes. Set to "0" for no limit.
$ft["settings"]["REQUEST_URI"]       = FALSE; // Installation path. You only need to set this if $_SERVER['REQUEST_URI'] is not being set by your server.
$ft["settings"]["HTTPS"] = FALSE; // Change to TRUE to enable HTTPS support.
$ft["settings"]["AUTOUPDATES"]       = "0"; // Number of days between checking for updates. Set to '0' to turn off.
$ft["settings"]["REMEMBERME"]        = FALSE; // Set to TRUE to enable the "remember me" feature at login.
$ft["settings"]["PLUGINDIR"]         = 'ft_plugins'; // Set to the path to your plugin folder. Do NOT include a trailing slash!
# Colours #
$ft["settings"]["COLOURONE"]         = "#326532"; // Dark background colour - also used on menu links.
$ft["settings"]["COLOURONETEXT"]     = "#fff"; // Text for the dark background.
$ft["settings"]["COLOURTWO"]         = "#DAE3DA"; // Brighter color (for table rows and sidebar background).
$ft["settings"]["COLOURTEXT"]        = "#000"; // Regular text colour.
$ft["settings"]["COLOURHIGHLIGHT"]   = "#ffc"; // Hightlight colour for status messages.

# Plugin settings #
$ft["plugins"]["decoder"] = TRUE;
$ft["plugins"]["decodercsv"] = TRUE;
$ft["plugins"]["encoder"] = TRUE;
//$ft["plugins"]["search"] = TRUE;
$ft["plugins"]["edit"] = array(
 "settings" => array(
   "editlist" => "txt json xml",
   "converttabs" => FALSE
 )
);
/*
$ft["plugins"]["tinymce"] = array(
  "settings" => array(
    "path" => "tinymce/jscripts/tiny_mce/tiny_mce.js",
    "list" => "html htm"
  )
);
*/

# Additional users - See guide at http://www.solitude.dk/filethingie/documentation/users #

/*
$ft['users']['REPLACE_WITH_USERNAME'] = array(
  'password' => 'REPLACE_WITH_PASSWORD', 
  'group' => 'REPLACE_WITH_GROUPNAME'
);
*/

# User groups for additional users -  - See guide at http://www.solitude.dk/filethingie/documentation/users #

/*
$ft['groups']['REPLACE_WITH_GROUPNAME'] = array(
  'DIR' => 'REPLACE_WITH_CUSTOM_DIR', 
);
*/


/**
 * Check if a login cookie is valid.
 *
 * @param $c
 *   The login cookie from $_COOKIE.
 * @return The username of the cookie user. FALSE if cookie is not valid.
 */
function ft_check_cookie($c) {
  global $ft;
  // Check primary user.
  if ($c == md5(USERNAME.PASSWORD)) {
    return USERNAME;
  }
  // Check users array.
	if (is_array($ft['users']) && sizeof($ft['users']) > 0) {
	  // Loop through users.
	  foreach ($ft['users'] as $user => $a) {
	    if ($c == md5($user.$a['password'])) {
	      return $user;
	    }
	  }
	}
	return FALSE;
}

/**
 * Check if directory is on the blacklist.
 *
 * @param $dir
 *   Directory path.
 * @return TRUE if directory is not blacklisted.
 */
function ft_check_dir($dir) {
	// Check against folder blacklist.
	if (FOLDERBLACKLIST != "") {
		$blacklist = explode(" ", FOLDERBLACKLIST);
		foreach ($blacklist as $c) {
      if (substr($dir, 0, strlen(ft_get_root().'/'.$c)) == ft_get_root().'/'.$c) {
        return FALSE;
      }      
		}
		return TRUE;
	} else {
		return TRUE;
	}
}

/**
 * Check if file actions are allowed in the current directory.
 *
 * @return TRUE is file actions are allowed.
 */
function ft_check_fileactions() {
  if (FILEACTIONS === TRUE) {
    // Uploads are universally turned on.
    return TRUE;
  } else if (FILEACTIONS == TRUE && FILEACTIONS == substr(ft_get_dir(), 0, strlen(FILEACTIONS))) {
    // Uploads are allowed in the current directory and subdirectories only.
    return TRUE;
  }
  return FALSE;  
}

/**
 * Check if file is on the blacklist.
 *
 * @param $file
 *   File name.
 * @return TRUE if file is not blacklisted.
 */
function ft_check_file($file) {
	// Check against file blacklist.
	if (FILEBLACKLIST != "") {
		$blacklist = explode(" ", strtolower(FILEBLACKLIST));
		if (in_array(strtolower($file), $blacklist)) {
			return FALSE;
		} else {
			return TRUE;
		}
	} else {
		return TRUE;
	}
}

/**
 * Check if file type is on the blacklist.
 *
 * @param $file
 *   File name.
 * @return TRUE if file is not blacklisted.
 */
function ft_check_filetype($file) {
	$type = strtolower(ft_get_ext($file));
	// Check if we are using a whitelist.
	if (FILETYPEWHITELIST != "") {
		// User wants a whitelist
		$whitelist = explode(" ", FILETYPEWHITELIST);
		if (in_array($type, $whitelist)) {
			return TRUE;
		} else {
			return FALSE;
		}		
	} else {
		// Check against file blacklist.
		if (FILETYPEBLACKLIST != "") {
			$blacklist = explode(" ", FILETYPEBLACKLIST);
			if (in_array($type, $blacklist)) {
				return FALSE;
			} else {
				return TRUE;
			}
		} else {
			return TRUE;
		}
	}
}

/**
 * Check if a user is authenticated to view the page or not. Must be called on all pages.
 *
 * @return TRUE if the user is authenticated.
 */
function ft_check_login() {
	global $ft;
  $valid_login = 0;
	if (LOGIN == TRUE) {
		if (empty($_SESSION['ft_user_'.MUTEX])) {
		  $cookie_mutex = str_replace('.', '_', MUTEX);
			// Session variable has not been set. Check if there is a valid cookie or login form has been submitted or return false.
      if (REMEMBERME == TRUE && !empty($_COOKIE['ft_user_'.$cookie_mutex])) {
        // Verify cookie.
        $cookie = ft_check_cookie($_COOKIE['ft_user_'.$cookie_mutex]);
        if (!empty($cookie)) {
  			  // Cookie valid. Login.
  				$_SESSION['ft_user_'.MUTEX] = $cookie;
  				ft_invoke_hook('loginsuccess', $cookie);
  				ft_redirect();          
        }
			}
			if (!empty($_POST['act']) && $_POST['act'] == "dologin") {
				// Check username and password from login form.
				if (!empty($_POST['ft_user']) && $_POST['ft_user'] == USERNAME && $_POST['ft_pass'] == PASSWORD) {
					// Valid login. 
					$_SESSION['ft_user_'.MUTEX] = USERNAME;
					$valid_login = 1;
				}
				// Default user was not valid, we check additional users (if any).
				if (is_array($ft['users']) && sizeof($ft['users']) > 0) {
					// Check username and password.
					if (array_key_exists($_POST['ft_user'], $ft['users']) && $ft['users'][$_POST['ft_user']]['password'] == $_POST['ft_pass']) {
						// Valid login.
						$_SESSION['ft_user_'.MUTEX] = $_POST['ft_user'];
						$valid_login = 1;
					}
				}
				if ($valid_login == 1) {
				  // Set cookie.
					if (!empty($_POST['ft_cookie']) && REMEMBERME) {
					  setcookie('ft_user_'.MUTEX, md5($_POST['ft_user'].$_POST['ft_pass']), time()+60*60*24*3);
					} else {
					  // Delete cookie
					  setcookie('ft_user_'.MUTEX, md5($_POST['ft_user'].$_POST['ft_pass']), time()-3600);
					}
					ft_invoke_hook('loginsuccess', $_POST['ft_user']);
					ft_redirect();
				} else {
				  ft_invoke_hook('loginfail', $_POST['ft_user']);
  				ft_redirect("act=error");				  
				}
			}
			return FALSE;
		} else {
			return TRUE;
		}
	} else {
		return TRUE;
	}
}

/**
 * Check if a move action is inside the file actions area if FILEACTIONS is set to a specific director.
 *
 * @param $dest
 *   The directory to move to.
 * @return TRUE if move action is allowed.
 */
function ft_check_move($dest) {
  if (FILEACTIONS === TRUE) {
    return TRUE;
  }
  // Check if destination is within the fileactions area.
  $dest = substr($dest, 0, strlen($dest));
  $levels = substr_count(substr(ft_get_dir(), strlen(FILEACTIONS)), '/');
  if ($levels <= substr_count($dest, '../')) {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**
 * Check if uploads are allowed in the current directory.
 *
 * @return TRUE if uploads are allowed.
 */
function ft_check_upload() {
  if (UPLOAD === TRUE) {
    // Uploads are universally turned on.
    return TRUE;
  } else if (UPLOAD == TRUE && UPLOAD == substr(ft_get_dir(), 0, strlen(UPLOAD))) {
    // Uploads are allowed in the current directory and subdirectories only.
    return TRUE;
  }
  return FALSE;  
}

/**
 * Check if a user exists.
 *
 * @param $username
 *   Username to check.
 * @return TRUE if user exists.
 */
function ft_check_user($username) {
  global $ft;
  if ($username == USERNAME) {
    return TRUE;
  } elseif (is_array($ft['users']) && sizeof($ft['users']) > 0 && array_key_exists($username, $ft['users'])) {
    return TRUE;
  }
  return FALSE;
}

/**
 * Check if the a new version of File Thingie is available.
 *
 * @return A string describing the results. Contains a changelog if a new version is available.
 */
function ft_check_version() {
	// Get newest version.
	if ($c = ft_get_url("http://www.solitude.dk/filethingie/versioninfo2.php?act=check&from=".urlencode('http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']))) {
	  $c = explode('||', $c);
		$version = trim($c[0]);
		$log = trim($c[1]);
		// Compare versions.
		if (version_compare($version, VERSION) == 1) {
			// New version available.
			return '<p>'.t('A new version of File Thingie (!version) is available.', array('!version' => $version)).'</p>'.$log.'<p><strong><a href="http://www.solitude.dk/filethingie/download">'.t('Download File Thingie !version', array('!version' => $version)).'</a></strong></p>';
		} else {
			// Running newest version.
			return '<p>'.t('No updates available.').'</p><ul><li>'.t('Your version:').' '.VERSION.'</li><li>'.t('Newest version:').' '.$version.'</li></ul>';
		}
		return "<p>".t('Newest version is:')." {$version}</p>";
	} else {
		return "<p class='error'>".t('Could not connect (possible error: URL wrappers not enabled).')."</p>";
	}
}

/**
 * Remove unwanted characters from the settings array.
 */
function ft_clean_settings($settings) {
  // TODO: Clean DIR, UPLOAD and FILEACTIONS so they can't start with ../
  return $settings;
}

/**
 * Run all system actions based on the value of $_REQUEST['act'].
 */
function ft_do_action() {
	if (!empty($_REQUEST['act'])) {

    // Only one callback action is allowed. So only the first hook that acts on an action is run.
    ft_invoke_hook('action', $_REQUEST['act']);

		# mkdir
		if ($_REQUEST['act'] == "createdir" && CREATE === TRUE) {
		  $_POST['newdir'] = trim($_POST['newdir']);
      if ($_POST['type'] == 'file') {
        // Check file against blacklists
        if (strlen($_POST['newdir']) > 0 && ft_check_filetype($_POST['newdir']) && ft_check_file($_POST['newdir'])) {
          // Create file.
  				$newfile = ft_get_dir()."/{$_POST['newdir']}";
  				if (file_exists($newfile)) {
  					// Redirect
            ft_set_message(t("File could not be created. File already exists."), 'error');
  					ft_redirect("dir=".$_REQUEST['dir']);
  				} elseif (@touch($newfile)) {
  					// Redirect.
  					ft_set_message(t("File created."));
  					ft_redirect("dir=".$_REQUEST['dir']);
  				} else {
  					// Redirect
  					ft_set_message(t("File could not be created."), 'error');
  					ft_redirect("dir=".$_REQUEST['dir']);
  				}
  			} else {
					// Redirect
					ft_set_message(t("File could not be created."), 'error');
					ft_redirect("dir=".$_REQUEST['dir']);
  			}
  		} elseif ($_POST['type'] == 'url') {
  		  // Create from URL.
        $newname = trim(substr($_POST['newdir'], strrpos($_POST['newdir'], '/')+1));
        if (strlen($newname) > 0 && ft_check_filetype($newname) && ft_check_file($newname)) {
          // Open file handlers.
          $rh = fopen($_POST['newdir'], 'rb');
          if ($rh === FALSE) {
  					ft_set_message(t("Could not open URL. Possible reason: URL wrappers not enabled."), 'error');
  					ft_redirect("dir=".$_REQUEST['dir']);
          }
          $wh = fopen(ft_get_dir().'/'.$newname, 'wb');
          if ($wh === FALSE) {
  					ft_set_message(t("File could not be created."), 'error');
  					ft_redirect("dir=".$_REQUEST['dir']);            
          }
          // Download anf write file.
          while (!feof($rh)) {
            if (fwrite($wh, fread($rh, 1024)) === FALSE) {
    					ft_set_message(t("File could not be saved."), 'error');
             }
          }
          fclose($rh);
          fclose($wh);
					ft_redirect("dir=".$_REQUEST['dir']);            
  			} else {
					// Redirect
					ft_set_message(t("File could not be created."), 'error');
					ft_redirect("dir=".$_REQUEST['dir']);
  			}
      } else {
  			// Create directory.
  			// Check input.
        // if (strstr($_POST['newdir'], ".")) {
  				// Throw error (redirect).
          // ft_redirect("status=createddirfail&dir=".$_REQUEST['dir']);
        // } else {
  				$_POST['newdir'] = ft_stripslashes($_POST['newdir']);
  				$newdir = ft_get_dir()."/{$_POST['newdir']}";
  				$oldumask = umask(0);
  				if (strlen($_POST['newdir']) > 0 && @mkdir($newdir, DIRPERMISSION)) {
  					ft_set_message(t("Directory created."));
  					ft_redirect("dir=".$_REQUEST['dir']);
  				} else {
  					// Redirect
  					ft_set_message(t("Directory could not be created."), 'error');
  					ft_redirect("dir=".$_REQUEST['dir']);
  				}
  				umask($oldumask);
        // }        
      }
		# Move
		} elseif ($_REQUEST['act'] == "move" && ft_check_fileactions() === TRUE) {
			// Check that both file and newvalue are set.
			$file = trim(ft_stripslashes($_REQUEST['file']));
			$dir = trim(ft_stripslashes($_REQUEST['newvalue']));
			if (substr($dir, -1, 1) != "/") {
				$dir .= "/";
			}
			// Check for level.
			if (substr_count($dir, "../") <= substr_count(ft_get_dir(), "/") && ft_check_move($dir) === TRUE) {
				$dir  = ft_get_dir()."/".$dir;
				if (!empty($file) && file_exists(ft_get_dir()."/".$file)) {
					// Check that destination exists and is a directory.
					if (is_dir($dir)) {
						// Move file.
						if (@rename(ft_get_dir()."/".$file, $dir."/".$file)) {
							// Success.
							ft_set_message(t("!old was moved to !new", array('!old' => $file, '!new' => $dir)));
							ft_redirect("dir={$_REQUEST['dir']}");
						} else {
							// Error rename failed.
							ft_set_message(t("!old could not be moved.", array('!old' => $file)), 'error');
							ft_redirect("dir={$_REQUEST['dir']}");
						}
					} else {
						// Error dest. isn't a dir or doesn't exist.
						ft_set_message(t("Could not move file. !old does not exist or is not a directory.", array('!old' => $dir)), 'error');
						ft_redirect("dir={$_REQUEST['dir']}");
					}
				} else {
					// Error source file doesn't exist.
					ft_set_message(t("!old could not be moved. It doesn't exist.", array('!old' => $file)), 'error');
					ft_redirect("dir={$_REQUEST['dir']}");
				}
			} else {
				// Error level
				ft_set_message(t("!old could not be moved outside the base directory.", array('!old' => $file)), 'error');
				ft_redirect("dir={$_REQUEST['dir']}");
			}
		# Delete
		} elseif ($_REQUEST['act'] == "delete" && ft_check_fileactions() === TRUE) {
			// Check that file is set.
			$file = ft_stripslashes($_REQUEST['file']);
			if (!empty($file) && ft_check_file($file)) {
				if (is_dir(ft_get_dir()."/".$file)) {
          if (DELETEFOLDERS == TRUE) {
            ft_rmdir_recurse(ft_get_dir()."/".$file);
          }
					if (!@rmdir(ft_get_dir()."/".$file)) {
					  ft_set_message(t("!old could not be deleted.", array('!old' => $file)), 'error');
						ft_redirect("dir={$_REQUEST['dir']}");
					} else {
					  ft_set_message(t("!old deleted.", array('!old' => $file)));
						ft_redirect("dir={$_REQUEST['dir']}");
					}
				} else {
					if (!@unlink(ft_get_dir()."/".$file)) {
					  ft_set_message(t("!old could not be deleted.", array('!old' => $file)), 'error');
						ft_redirect("dir={$_REQUEST['dir']}");
					} else {
					  ft_set_message(t("!old deleted.", array('!old' => $file)));
						ft_redirect("dir={$_REQUEST['dir']}");
					}
				}
			} else {
			  ft_set_message(t("!old could not be deleted.", array('!old' => $file)), 'error');
				ft_redirect("dir={$_REQUEST['dir']}");
			}
		# Rename && Duplicate && Symlink
		} elseif ($_REQUEST['act'] == "rename" || $_REQUEST['act'] == "duplicate" || $_REQUEST['act'] == "symlink" && ft_check_fileactions() === TRUE) {
			// Check that both file and newvalue are set.
			$old = trim(ft_stripslashes($_REQUEST['file']));
			$new = trim(ft_stripslashes($_REQUEST['newvalue']));
			if ($_REQUEST['act'] == 'rename') {
			  $m['typefail'] = t("!old was not renamed to !new (type not allowed).", array('!old' => $old, '!new' => $new));
			  $m['writefail'] = t("!old could not be renamed (write failed).", array('!old' => $old));
			  $m['destfail'] = t("File could not be renamed to !new since it already exists.", array('!new' => $new));
			  $m['emptyfail'] = t("File could not be renamed since you didn't specify a new name.");
			} elseif ($_REQUEST['act'] == 'duplicate') {
			  $m['typefail'] = t("!old was not duplicated to !new (type not allowed).", array('!old' => $old, '!new' => $new));
			  $m['writefail'] = t("!old could not be duplicated (write failed).", array('!old' => $old));
			  $m['destfail'] = t("File could not be duplicated to !new since it already exists.", array('!new' => $new));
			  $m['emptyfail'] = t("File could not be duplicated since you didn't specify a new name.");
			} elseif ($_REQUEST['act'] == 'symlink') {
			  $m['typefail'] = t("Could not create symlink to !old (type not allowed).", array('!old' => $old, '!new' => $new));
			  $m['writefail'] = t("Could not create symlink to !old (write failed).", array('!old' => $old));
			  $m['destfail'] = t("Could not create symlink !new since it already exists.", array('!new' => $new));
			  $m['emptyfail'] = t("Symlink could not be created since you didn't specify a name.");
			}
			if (!empty($old) && !empty($new)) {
				if (ft_check_filetype($new) && ft_check_file($new)) {
					// Make sure destination file doesn't exist.
					if (!file_exists(ft_get_dir()."/".$new)) {
						// Check that file exists.
						if (is_writeable(ft_get_dir()."/".$old)) {
							if ($_REQUEST['act'] == "rename") {
								if (@rename(ft_get_dir()."/".$old, ft_get_dir()."/".$new)) {
									// Success.
									ft_set_message(t("!old was renamed to !new", array('!old' => $old, '!new' => $new)));
									ft_redirect("dir={$_REQUEST['dir']}");
								} else {
									// Error rename failed.
									ft_set_message(t("!old could not be renamed.", array('!old' => $old)), 'error');
									ft_redirect("dir={$_REQUEST['dir']}");
								}
							} elseif ($_REQUEST['act'] == 'symlink') {
							  if (ADVANCEDACTIONS == TRUE) {
  								if (@symlink(realpath(ft_get_dir()."/".$old), ft_get_dir()."/".$new)) {
  								  @chmod(ft_get_dir()."/{$new}", PERMISSION);
  									// Success.
  									ft_set_message(t("Created symlink !new", array('!old' => $old, '!new' => $new)));
  									ft_redirect("dir={$_REQUEST['dir']}");
  								} else {
  									// Error symlink failed.
  									ft_set_message(t("Symlink to !old could not be created.", array('!old' => $old)), 'error');
  									ft_redirect("dir={$_REQUEST['dir']}");
  								}							    
							  }
							} else {
								if (@copy(ft_get_dir()."/".$old, ft_get_dir()."/".$new)) {
									// Success.
									ft_set_message(t("!old was duplicated to !new", array('!old' => $old, '!new' => $new)));
									ft_redirect("dir={$_REQUEST['dir']}");
								} else {
									// Error rename failed.
									ft_set_message(t("!old could not be duplicated.", array('!old' => $old)), 'error');
									ft_redirect("dir={$_REQUEST['dir']}");						
								}
							}
						} else {
							// Error old file isn't writeable.
							ft_set_message($m['writefail'], 'error');
							ft_redirect("dir={$_REQUEST['dir']}");
						}
					} else {
						// Error destination exists.
						ft_set_message($m['destfail'], 'error');
						ft_redirect("dir={$_REQUEST['dir']}");
					}
				} else {
					// Error file type not allowed.
					ft_set_message($m['typefail'], 'error');
					ft_redirect("dir={$_REQUEST['dir']}");
				}
			} else {
				// Error. File name not set.
				ft_set_message($m['emptyfail'], 'error');
				ft_redirect("dir={$_REQUEST['dir']}");
			}
		# upload
		} elseif ($_REQUEST['act'] == "upload" && ft_check_upload() === TRUE && (LIMIT <= 0 || LIMIT > ROOTDIRSIZE)) {
			// If we are to upload a file we will do so.
			$msglist = 0;
			foreach ($_FILES as $k => $c) {
				if (!empty($c['name'])) {
					$c['name'] = ft_stripslashes($c['name']);
					if ($c['error'] == 0) {
						// Upload was successfull
						if (ft_check_filetype($c['name']) && ft_check_file($c['name'])) {
							if (file_exists(ft_get_dir()."/{$c['name']}")) {
							  $msglist++;
							  ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("File already exists"), 'error');
							} else {
								if (@move_uploaded_file($c['tmp_name'], ft_get_dir()."/{$c['name']}")) {
									@chmod(ft_get_dir()."/{$c['name']}", PERMISSION);
									// Success!
  							  $msglist++;
                  ft_set_message(t('!file was uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))));
                  ft_invoke_hook('upload', ft_get_dir(), $c['name']);
								} else {
									// File couldn't be moved. Throw error.
  							  $msglist++;
                  ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("File couldn't be moved"), 'error');
								}
							}
						} else {
							// File type is not allowed. Throw error.
						  $msglist++;
              ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("File type not allowed"), 'error');
						}
					} else {
						// An error occurred.
						switch($_FILES["localfile"]["error"]) {
							case 1:
						    $msglist++;
							  ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("The file was too large"), 'error');
								break;
							case 2:
						    $msglist++;
							  ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("The file was larger than MAXSIZE setting."), 'error');
								break;
							case 3:
						    $msglist++;
							  ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("Partial upload. Try again"), 'error');
								break;
							case 4:
						    $msglist++;
							  ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("No file was uploaded. Please try again"), 'error');
								break;
							default:
						    $msglist++;
							  ft_set_message(t('!file was not uploaded.', array('!file' => ft_get_nice_filename($c['name'], 20))) . ' ' . t("Unknown error"), 'error');
								break;
						}
					}
				}
			}
			if ($msglist > 0) {
				ft_redirect("dir=".$_REQUEST['dir']);
			} else {
			  ft_set_message(t("Upload failed."), 'error');
				ft_redirect("dir=".$_REQUEST['dir']);
			}
    # Unzip
    } elseif ($_REQUEST['act'] == "unzip" && ft_check_fileactions() === TRUE) {
			// Check that file is set.
			$file = ft_stripslashes($_REQUEST['file']);
			if (!empty($file) && ft_check_file($file) && ft_check_filetype($file) && strtolower(ft_get_ext($file)) == 'zip' && is_file(ft_get_dir()."/".$file)) {
			  $escapeddir = escapeshellarg(ft_get_dir()."/");
			  $escapedfile = escapeshellarg(ft_get_dir()."/".$file);
				if (!@exec("unzip -n ".$escapedfile." -d ".$escapeddir)) {
          ft_set_message(t("!old could not be unzipped.", array('!old' => $file)), 'error');
					ft_redirect("dir={$_REQUEST['dir']}");
				} else {
          ft_set_message(t("!old unzipped.", array('!old' => $file)));
					ft_redirect("dir={$_REQUEST['dir']}");
				}
			} else {
        ft_set_message(t("!old could not be unzipped.", array('!old' => $file)), 'error');
				ft_redirect("dir={$_REQUEST['dir']}");
			}
    # chmod
    } elseif ($_REQUEST['act'] == "chmod" && ft_check_fileactions() === TRUE && ADVANCEDACTIONS == TRUE) {
			// Check that file is set.
			$file = ft_stripslashes($_REQUEST['file']);
			if (!empty($file) && ft_check_file($file) && ft_check_filetype($file)) {
  			// Check that chosen permission i valid
  			if (is_numeric($_REQUEST['newvalue'])) {
  			  $chmod = $_REQUEST['newvalue'];
  			  if (substr($chmod, 0, 1) == '0') {
  			    $chmod = substr($chmod, 0, 4);
  			  } else {
  			    $chmod = '0'.substr($chmod, 0, 3);  			    
  			  }
  			  // Chmod
  			  if (@chmod(ft_get_dir()."/".$file, intval($chmod, 8))) {
  			    ft_set_message(t("Permissions changed for !old.", array('!old' => $file)));
  			    ft_redirect("dir={$_REQUEST['dir']}");
    			  clearstatcache();  			    
  			  } else {
  			    ft_set_message(t("Could not change permissions for !old.", array('!old' => $file)), 'error');
    				ft_redirect("dir={$_REQUEST['dir']}");
  			  }
  			} else {
			    ft_set_message(t("Could not change permissions for !old.", array('!old' => $file)), 'error');
  				ft_redirect("dir={$_REQUEST['dir']}");
  			}
			} else {
		    ft_set_message(t("Could not change permissions for !old.", array('!old' => $file)), 'error');
				ft_redirect("dir={$_REQUEST['dir']}");
			}
		# logout
		} elseif ($_REQUEST['act'] == "logout") {
		  ft_invoke_hook('logout', $_SESSION['ft_user_'.MUTEX]);
			$_SESSION = array();
			if (isset($_COOKIE[session_name()])) {
			   setcookie(session_name(), '', time()-42000, '/');
			}
			session_destroy();
			// Delete persistent cookie
		  setcookie('ft_user_'.MUTEX, '', time()-3600);
			ft_redirect();
		}
	}
}

/**
 * Convert PHP ini shorthand notation for file size to byte size.
 *
 * @return Size in bytes.
 */
function ft_get_bytes($val) {
	$val = trim($val);
	$last = strtolower($val{strlen($val)-1});
	switch($last) {
		// The 'G' modifier is available since PHP 5.1.0
		case 'g':
			$val *= 1024;
		case 'm':
			$val *= 1024;
		case 'k':
			$val *= 1024;
	}
	return $val;
}

/**
 * Get the total disk space consumed by files available to the current user.
 * Files and directories on blacklists are not counted.
 *
 * @param $dirname
 *   Name of the directory to scan.
 * @return Space consumed by this directory in bytes (not counting files and directories on blacklists).
 */
function ft_get_dirsize($dirname) {
  if (!is_dir($dirname) || !is_readable($dirname)) {
    return false;
  }
  $dirname_stack[] = $dirname;
  $size = 0;
  do {
    $dirname = array_shift($dirname_stack);
    $handle = opendir($dirname);
    while (false !== ($file = readdir($handle))) {
      if ($file != '.' && $file != '..' && is_readable($dirname . '/' . $file)) {
        if (is_dir($dirname . '/' . $file)) {
          if (ft_check_dir($dirname . '/' . $file)) {
            $dirname_stack[] = $dirname . '/' . $file;
          }
        } else {
          if (ft_check_file($file) && ft_check_filetype($file)) {
            $size += filesize($dirname . '/' . $file);
          }          
        }
      }
    }
    closedir($handle);
  } while (count($dirname_stack) > 0);
  return $size;
}

/**
 * Get the current directory.
 *
 * @return The current directory.
 */
function ft_get_dir() {
	if (empty($_REQUEST['dir'])) {
		return ft_get_root();
	} else {
		return ft_get_root().$_REQUEST['dir'];
	}
}
/**
 * Get file extension from a file name.
 *
 * @param $name
 *   File name.
 * @return The file extension without the '.'
 */
function ft_get_ext($name) {
	if (strstr($name, ".")) {
		$ext = str_replace(".", "", strrchr($name, "."));
	} else {
		$ext = "";
	}
	return $ext;
}

/**
 * Get a list of files in a directory with metadata.
 *
 * @param $dir
 *   The directory to scan.
 * @param $sort
 *   Sorting parameter. Possible values: name, type, size, date. Defaults to 'name'.
 * @return An array of files. Each item is an array:
 *   array(
 *     'name' => '', // File name.
 *     'shortname' => '', // File name.
 *     'type' => '', // 'file' or 'dir'.
 *     'ext' => '', // File extension.
 *     'writeable' => '', // TRUE if writeable.
 *     'perms' => '', // Permissions.
 *     'modified' => '', // Last modified. Unix timestamp.
 *     'size' => '', // File size in bytes.
 *     'extras' => '' // Array of extra classes for this file.
 *   )
 */
function ft_get_filelist($dir, $sort = 'name') {
	$filelist = array();
	$subdirs = array();
	if (ft_check_dir($dir) && $dirlink = @opendir($dir)) {
		// Creates an array with all file names in current directory.
		while (($file = readdir($dirlink)) !== false) {
			if ($file != "." && $file != ".." && ((!is_dir("{$dir}/{$file}") && ft_check_file($file) && ft_check_filetype($file)) || is_dir("{$dir}/{$file}") && ft_check_dir("{$dir}/{$file}"))) { // Hide these two special cases and files and filetypes in blacklists.
				$c = array();
				$c['name'] = $file;
        // $c['shortname'] = ft_get_nice_filename($file, 20);
        $c['shortname'] = $file;
				$c['type'] = "file";
				$c['ext'] = ft_get_ext($file);
				$c['writeable'] = is_writeable("{$dir}/{$file}");
				
        // Grab extra options from plugins.
				$c['extras'] = array();
				$c['extras'] = ft_invoke_hook('fileextras', $file, $dir);
				
				// File permissions.
				if ($c['perms'] = @fileperms("{$dir}/{$file}")) {
  				if (is_dir("{$dir}/{$file}")) {
            $c['perms'] = substr(base_convert($c['perms'], 10, 8), 2);
          } else {
            $c['perms'] = substr(base_convert($c['perms'], 10, 8), 3);            
          }
				}
        $c['modified'] = @filemtime("{$dir}/{$file}");
				$c['size'] = @filesize("{$dir}/{$file}");
				if (ft_check_dir("{$dir}/{$file}") && is_dir("{$dir}/{$file}")) {
					$c['size'] = 0;
					$c['type'] = "dir";
					if ($sublink = @opendir("{$dir}/{$file}")) {
						while (($current = readdir($sublink)) !== false) {
							if ($current != "." && $current != ".." && ft_check_file($current)) {
								$c['size']++;
							}
						}
						closedir($sublink);
					}
					$subdirs[] = $c;
				} else {
					$filelist[] = $c;
				}
			}
		}
		closedir($dirlink);
    // sort($filelist);
		
		// Obtain a list of columns
		$ext = array();
		$name = array();
		$date = array();
		$size = array();
    foreach ($filelist as $key => $row) {
      $ext[$key]  = strtolower($row['ext']);
      $name[$key] = strtolower($row['name']);
      $date[$key] = $row['modified'];
      $size[$key] = $row['size'];
    }

    if ($sort == 'type') {
      // Sort by file type and then name.
      array_multisort($ext, SORT_ASC, $name, SORT_ASC, $filelist);      
    } elseif ($sort == 'size') {
      // Sort by filesize date and then name.
      array_multisort($size, SORT_ASC, $name, SORT_ASC, $filelist);      
    } elseif ($sort == 'date') {
      // Sort by last modified date and then name.
      array_multisort($date, SORT_DESC, $name, SORT_ASC, $filelist);      
    } else {
      // Sort by file name.
      array_multisort($name, SORT_ASC, $filelist);      
    }
		// Always sort dirs by name.
		sort($subdirs);
		return array_merge($subdirs, $filelist);
	} else {
		return "dirfail";
	}
}

/**
 * Determine the max. size for uploaded files.
 *
 * @return Human-readable string of upload limit.
 */
function ft_get_max_upload() {
  $post_max = ft_get_bytes(ini_get('post_max_size'));
  $upload = ft_get_bytes(ini_get('upload_max_filesize'));
  // Compare ini settings.
  $max = (($post_max > $upload) ? $upload : $post_max);
  // Compare with MAXSIZE.
  if ($max > MAXSIZE) {
    $max = MAXSIZE;
  }
  return ft_get_nice_filesize($max);
}

/**
 * Shorten a file name to a given length maintaining the file extension.
 *
 * @param $name
 *   File name.
 * @param $limit
 *   The maximum length of the file name.
 * @return The shortened file name.
 */
function ft_get_nice_filename($name, $limit = -1) {
  if ($limit > 0) {
    $noext = $name;
    if (strstr($name, '.')) {
      $noext = substr($name, 0, strrpos($name, '.'));      
    }
    $ext = ft_get_ext($name);
    if (strlen($noext)-3 > $limit) {
      $name = substr($noext, 0, $limit).'...';
      if ($ext != '') {
        $name = $name. '.' .$ext;
      }
    }
  }
  return $name;
}

/**
 * Convert a number of bytes to a human-readable format.
 *
 * @param $size
 *   Integer. File size in bytes.
 * @return String. Human-readable file size.
 */
function ft_get_nice_filesize($size) {
  if (empty($size)) {
    return "&mdash;";
	} elseif (strlen($size) > 6) { // Convert to megabyte
		return round($size/(1024*1024), 2)."&nbsp;MB";
	} elseif (strlen($size) > 4 || $size > 1024) { // Convert to kilobyte
		return round($size/1024, 0)."&nbsp;Kb";
	} else {
		return $size."&nbsp;b";
	}
}

/**
 * Get the root directory.
 *
 * @return The root directory.
 */
function ft_get_root() {
	return DIR;
}

/**
 * Get the name of the File Thingie file. Used in <form> actions.
 *
 * @return File name.
 */
function ft_get_self() {
	return basename($_SERVER['PHP_SELF']);
}

/**
 * Retrieve the contents of a URL.
 *
 * @return The contents of the URL as a string.
 */
function ft_get_url($url) {
	$url_parsed = parse_url($url);
	$host = $url_parsed["host"];
	$port = 0;
	$in = '';
	if (!empty($url_parsed["port"])) {
  	$port = $url_parsed["port"];	  
	}
	if ($port==0) {
		$port = 80;
	}
	$path = $url_parsed["path"];
	if ($url_parsed["query"] != "") {
		$path .= "?".$url_parsed["query"];
	}
	$out = "GET $path HTTP/1.0\r\nHost: $host\r\n\r\n";
	$fp = fsockopen($host, $port, $errno, $errstr, 30);
	fwrite($fp, $out);
	$body = false;
	while ($fp && !feof($fp)) {
		$s = fgets($fp, 1024);
		if ( $body ) {
			$in .= $s;
		}
		if ( $s == "\r\n" ) {
			$body = true;
		}
	}
	fclose($fp);
	return $in;
}
/**
 * Get users in a group.
 *
 * @param $group
 *   Name of group.
 * @return Array of usernames.
 */
function ft_get_users_by_group($group) {
  global $ft;
  $userlist = array();
  foreach ($ft['users'] as $user => $c) {
    if (!empty($c['group']) && $c['group'] == $group) {
      $userlist[] = $user;
    }
  }
  return $userlist;
}

/**
 * Invoke a hook in all loaded plugins.
 *
 * @param $hook
 *   Name of the hook to invoke.
 * @param ...
 *   Arguments to pass to the hook.
 * @return Array of results from all hooks run.
 */
function ft_invoke_hook() {
  global $ft;
  $args = func_get_args();
  $hook = $args[0];
  unset($args[0]);  
  // Loop through loaded plugins.
  $return = array();
  if (isset($ft['loaded_plugins']) && is_array($ft['loaded_plugins'])) {
    foreach ($ft['loaded_plugins'] as $name) {
      if (function_exists('ft_'.$name.'_'.$hook)) {
        $result = call_user_func_array('ft_'.$name.'_'.$hook, $args);
        if (isset($result) && is_array($result)) {
          $return = array_merge_recursive($return, $result);
        }
        else if (isset($result)) {
          $return[] = $result;
        }
      }
    }
  }
  return $return;
}

/**
 * Create HTML for the page body. Defaults to a file list.
 */
function ft_make_body() {
	$str = "";

  // Make system messages.
	$status = '';
	if (ft_check_upload() === TRUE && is_writeable(ft_get_dir()) && (LIMIT > 0 && LIMIT < ROOTDIRSIZE)) {
	  $status = '<p class="error">' . t('Upload disabled. Total disk space use of !size exceeds the limit of !limit.', array('!limit' => ft_get_nice_filesize(LIMIT), '!size' => ft_get_nice_filesize(ROOTDIRSIZE))) . '</p>';
	}
	$status .= ft_make_messages();
	if (empty($status)) {
    $str .= "<div id='status' class='hidden'></div>";
	} else {
		$str .= "<div id='status' class='section'>{$status}</div>";
	}
	
	// Invoke page hook if an action has been set.
	if (!empty($_REQUEST['act'])) {
    return $str . '<div id="main">'.implode("\r\n", ft_invoke_hook('page', $_REQUEST['act'])).'</div>';
	}
	
	// If no action has been set, show a list of files.
	
	if (empty($_REQUEST['act']) && (empty($_REQUEST['status']) || $_REQUEST['status'] != "dirfail")) { // No action set - we show a list of files if directory has been proven openable.
    $totalsize = 0;
    // Set sorting type. Default to 'name'.
    $sort = 'name';
    $cookie_mutex = str_replace('.', '_', MUTEX);
    // If there's a GET value, use that.
    if (!empty($_GET['sort'])) {
      // Set the cookie.
      setcookie('ft_sort_'.MUTEX, $_GET['sort'], time()+60*60*24*365);
      $sort = $_GET['sort'];
    } elseif (!empty($_COOKIE['ft_sort_'.$cookie_mutex])) {
      // There's a cookie, we'll use that.
      $sort = $_COOKIE['ft_sort_'.$cookie_mutex];
    }
		$files = ft_get_filelist(ft_get_dir(), $sort);
		if (!is_array($files)) { 
			// List couldn't be fetched. Throw error.
      // ft_set_message(t("Could not open directory."), 'error');
      // ft_redirect();
      $str .= '<p class="error">'.t("Could not open directory.").'</p>';
		} else {			
			// Show list of files in a table.
			$colspan = 3;
			if (SHOWDATES) {
			  $colspan = 4;
			}
			$str .= "<table id='filelist'>";
			$str .= "<thead><tr><th colspan=\"{$colspan}\"><div style='float:left;'>".t('Files')."</div>";
      $str .= "<form action='".ft_get_self()."' id='sort_form' method='get'><div><!--<label for='sort'>Sort by: </label>--><select id='sort' name='sort'>";
      $sorttypes = array('name' => t('Sort by name'), 'size' => t('Sort by size'), 'type' => t('Sort by type'), 'date' => t('Sort by date'));
      foreach ($sorttypes as $k => $v) {
        $str .= "<option value='{$k}'";
        if ($sort == $k) {
          $str .= " selected='selected'";
        }
        $str .= ">{$v}</option>";
      }
      $str .= "</select><input type=\"hidden\" name=\"dir\" value=\"".$_REQUEST['dir']."\" /></div></form></th>";
			$str .= "</tr></thead>";
			$str .= "<tbody>";
			$countfiles = 0;
			$countfolders = 0;
			if (count($files) <= 0) {
				$str .= "<tr><td colspan='{$colspan}' class='error'>".t('Directory is empty.')."</td></tr>";
			} else {
				$i = 0;
				$previous = $files[0]['type'];
				foreach ($files as $c) {
					$odd = "";
					$class = '';
					if ($c['writeable']) {
						$class = "show writeable ";
					}
					if ($c['type'] == 'dir' && $c['size'] == 0) {
					  $class .= " empty";
					}
          // Loop through extras and set classes.
					foreach ($c['extras'] as $extra) {
					  $class .= " {$extra}";
					}
					
					if (isset($c['perms'])) {
						$class .= " perm-{$c['perms']} ";
					}
					if (!empty($_GET['highlight']) && $c['name'] == $_GET['highlight']) {
						$class .= " highlight ";
						$odd = "highlight ";
					}
					if ($i%2 != 0) {
						$odd .= "odd";
					}
					if ($previous != $c['type']) {
						// Insert seperator.
						$odd .= " seperator ";
					}
					$previous = $c['type'];
					$str .= "<tr class='{$c['type']} $odd'>";
					if ($c['writeable'] && ft_check_fileactions() === TRUE) {
						$str .= "<td class='details'><span class='{$class}'>&loz;</span><span class='hide' style='display:none;'>&loz;</span></td>";						
					} else {
						$str .= "<td class='details'>&mdash;</td>";
					}
				  $plugin_data = implode('', ft_invoke_hook('filename', $c['name']));
					if ($c['type'] == "file"){
					  $link = "<a href=\"".ft_get_dir()."/".rawurlencode($c['name'])."\" title=\"" .t('Show !file', array('!file' => $c['name'])). "\">{$c['shortname']}</a>";
					  if (HIDEFILEPATHS == TRUE) {
					    $link = ft_make_link($c['shortname'], 'method=getfile&amp;dir='.rawurlencode($_REQUEST['dir']).'&amp;file='.$c['name'], t('Show !file', array('!file' => $c['name'])));
					  }
						$str .= "<td class='name'>{$link}{$plugin_data}</td><td class='size'>".ft_get_nice_filesize($c['size']);
						$countfiles++;
					} else {
						$str .= "<td class='name'>".ft_make_link($c['shortname'], "dir=".rawurlencode($_REQUEST['dir'])."/".rawurlencode($c['name']), t("Show files in !folder", array('!folder' => $c['name'])))."{$plugin_data}</td><td class='size'>{$c['size']} ".t('files');
						$countfolders++;
					}
					// Add filesize to total.
					if ($c['type'] == 'file') {
					  $totalsize = $totalsize+$c['size'];
					}
					if (SHOWDATES) {
            if (isset($c['modified']) && $c['modified'] > 0) {
              $str .= "</td><td class='date'>".date(SHOWDATES, $c['modified'])."</td></tr>";
            } else {
              $str .= "</td><td class='date'>&mdash;</td></tr>";
            }
          }
          else {
            $str .= "</td></tr>";
          }
					$i++;
				}
			}
			if ($totalsize == 0) {
			  $totalsize = '';
			} else {
			  $totalsize = " (".ft_get_nice_filesize($totalsize).")";
			}
			$str .= "</tbody><tfoot><tr><td colspan=\"{$colspan}\">".$countfolders." ".t('folders')." - ".$countfiles." ".t('files')."{$totalsize}</td></tr></tfoot>";
			$str .= "</table>";
		}
	}
	return $str;
}

/**
 * Create HTML for page footer.
 */
function ft_make_footer() {
	return "<div id=\"footer\"><p><a href=\"http://www.solitude.dk/filethingie/\" target=\"_BLANK\">File Thingie &bull; PHP File Manager</a> &copy; <!-- Copyright --> 2003-".date("Y")." <a href=\"http://www.solitude.dk\" target=\"_BLANK\">Andreas Haugstrup Pedersen</a>.</p><p><a href=\"http://www.solitude.dk/filethingie/documentation\" target=\"_BLANK\">".t('Online documentation')."</a> &bull; <a href='http://www.solitude.dk/filethingie/download' id=\"versioncheck\" target=\"_BLANK\">".t('Check for new version')."</a></p><div id='versioninfo'></div></div>";
}

/**
 * Create HTML for top header that shows breadcumb navigation.
 */
function ft_make_header() {
  global $ft;
	$str = "<h1 id='title'>".ft_make_link(t("Home"), '', t("Go to home folder"))." ";
	if (empty($_REQUEST['dir'])) {
		$str .= "/</h1>";
	} else {
		// Get breadcrumbs.
		if (!empty($_REQUEST['dir'])) {
			$crumbs = explode("/", $_REQUEST['dir']);
			// Remove first empty element.
			unset($crumbs[0]);
			// Output breadcrumbs.
			$path = "";
			foreach ($crumbs as $c) {
				$path .= "/{$c}";
				$str .= "/";
				$str .= ft_make_link($c, "dir=".rawurlencode($path), t("Go to folder"));
			}
		}
		$str .= "</h1>";		
	}
	// Display logout link.
  if (LOGIN == TRUE) {
	  $str .= '<div id="logout"><p>';
	  if (isset($ft['users']) && @count($ft['users']) > 0 && LOGIN == TRUE) {
	    $str .= t('Logged in as !user ', array('!user' => $_SESSION['ft_user_'.MUTEX]));
	  }
	  $str .= ft_make_link(t("[logout]"), "act=logout", t("Logout of File Thingie")).'</p>';
	  $str .= '<div id="secondary_menu">' . implode("", ft_invoke_hook('secondary_menu')) . '</div>';
	  $str .= '</div>';
	}
	return $str;
}

/**
 * Create HTML for error message in case output was sent to the browser.
 */
function ft_make_headers_failed() {
	return "<h1>File Thingie Cannot Run</h1><div style='margin:1em;width:76ex;'><p>Your copy of File Thingie has become damaged and will not function properly. The most likely explanation is that the text editor you used when setting up your username and password added invisible garbage characters. Some versions of Notepad on Windows are known to do this.</p><p>To use File Thingie you should <strong><a href='http://www.solitude.dk/filethingie/'>download a fresh copy</a></strong> from the official website and use a different text editor when editing the file. On Windows you may want to try using <a href='http://www.editpadpro.com/editpadlite.html'>EditPad Lite</a> as your text editor.</p></div>";
}

/**
 * Create an internal HTML link.
 *
 * @param $text
 *   Link text.
 * @param $query
 *   The query string for the link. Optional.
 * @param $title
 *   String for the HTML title attribute. Optional.
 * @return String containing the HTML link.
 */
function ft_make_link($text, $query = "", $title = "") {
	$str = "<a href=\"".ft_get_self();
	if (!empty($query)) {
		$str .= "?{$query}";
	}
	$str .= "\"";
	if (!empty($title)) {
		$str .= "title=\"{$title}\"";
	}	
	$str .= ">{$text}</a>";
	return $str;
}

/**
 * Create HTML for login box.
 */
function ft_make_login() {
	$str = "<h1>".t('File Thingie Login')."</h1>";
	$str .= '<form action="'.ft_get_self().'" method="post" id="loginbox">';
	if (!empty($_REQUEST['act']) && $_REQUEST['act'] == "error") {
		$str .= "<p class='error'>".t('Invalid username or password')."</p>";
	}
	$str .= '<div>
			<div>
				<label for="ft_user" class="login"><input type="text" size="25" name="ft_user" id="ft_user" tabindex="1" /> '.t('Username:').'</label>
			</div>
			<div>
				<label for="ft_pass" class="login"><input type="password" size="25" name="ft_pass" id="ft_pass" tabindex="2" /> '.t('Password:').'</label>
				<input type="hidden" name="act" value="dologin" />
			</div>  <div class="checkbox">
    			  <input type="submit" value="'.t('Login').'" id="login_button" tabindex="10" />';
	if (REMEMBERME) {
		$str .= '<label for="ft_cookie" id="cookie_label"><input type="checkbox" name="ft_cookie" id="ft_cookie" tabindex="3" /> '.t('Remember me').'</label>';
	}
	$str .= '</div></div>
	</form>';    
	return $str;
}

/**
 * Create HTML for current status messages and reset status messages.
 */
function ft_make_messages() {
  $str = '';
  $msgs = array();
  if (isset($_SESSION['ft_status']) && is_array($_SESSION['ft_status'])) {
    foreach ($_SESSION['ft_status'] as $type => $messages) {
      if (is_array($messages)) {
        foreach ($messages as $m) {
          $msgs[] = "<p class='{$type}'>{$m}</p>";
        }
      }
    }
    // Reset messages.
    unset($_SESSION['ft_status']);
  }
  if (count($msgs) == 1) {
    return $msgs[0];
  } elseif (count($msgs) > 1) {
    $str .= "<ul>";
    foreach ($msgs as $c) {
      $str .= "<li>{$c}</li>";
    }
    $str .= "</ul>";    
  }
  return $str;
}

/**
 * Create and output <script> tags for the page.
 */
function ft_make_scripts() {
  global $ft;
  $scripts = array();
  if (INSTALL != "SIMPLE") {
    $scripts[] = 'jquery-1.2.1.pack.js';
    $scripts[] = 'filethingie.js';
    if (AUTOUPDATES != "0") {
      $scripts[] = 'jquery.cookie.js';
    }    
  }
  $result = ft_invoke_hook('add_js_file');
  $scripts = array_merge($scripts, $result);
  foreach ($scripts as $c) {
    echo "<script type='text/javascript' charset='utf-8' src='{$c}'></script>\r\n";
  }
}

/**
 * Create inline javascript for the HTML footer.
 *
 * @return String containing inline javascript.
 */
function ft_make_scripts_footer() {
  $result = ft_invoke_hook('add_js_call_footer');
  $str = "\r\n";
  if (count($result) > 0) {
    $str .= '<script type="text/javascript" charset="utf-8">';
    $str .= implode('', $result);
    $str .= '</script>';    
  }
  return $str;
}

/**
 * Create HTML for sidebar.
 */
function ft_make_sidebar() {
	$str = '<div id="sidebar">';
  // $status = '';
  // if (ft_check_upload() === TRUE && is_writeable(ft_get_dir()) && (LIMIT > 0 && LIMIT < ROOTDIRSIZE)) {
  //   $status = '<p class="alarm">' . t('Upload disabled. Total disk space use of !size exceeds the limit of !limit.', array('!limit' => ft_get_nice_filesize(LIMIT), '!size' => ft_get_nice_filesize(ROOTDIRSIZE))) . '</p>';
  // }
  // $status .= ft_make_messages();
  // if (empty($status)) {
  //     $str .= "<div id='status' class='hidden'></div>";
  // } else {
  //  $str .= "<div id='status' class='section'><h2>".t('Results')."</h2>{$status}</div>";
  // }
	if (ft_check_upload() === TRUE && is_writeable(ft_get_dir())) {
	  if (LIMIT <= 0 || LIMIT > ROOTDIRSIZE) {
    	$str .= '
    	<div class="section" id="create">
    		<h2>'.t('Upload files').'</h2>
    		<form action="'.ft_get_self().'" method="post" enctype="multipart/form-data">
    			<div id="uploadsection">
    				<input type="hidden" name="MAX_FILE_SIZE" value="'.MAXSIZE.'" />
    				<input type="file" class="upload" name="localfile" id="localfile-0" size="12" />
    				<input type="hidden" name="act" value="upload" />
    				<input type="hidden" name="dir" value="'.$_REQUEST['dir'].'" />
    			</div>
    			<div id="uploadbutton">
    				<input type="submit" name="submit" value="'.t('Upload').'" />
    			</div>
          <div class="info">' . t('Max:') . ' <strong>' . ft_get_max_upload() . ' / ' . ft_get_nice_filesize((ft_get_bytes(ini_get('upload_max_filesize')) < ft_get_bytes(ini_get('post_max_size')) ? ft_get_bytes(ini_get('upload_max_filesize')) : ft_get_bytes(ini_get('post_max_size')))) . '</strong></div>
      		<div style="clear:both;"></div>
    		</form>
    	</div>';
	  }
	}
	if (CREATE) {
		$str .= '
	<div class="section" id="new">
		<h2>'.t('Create folder').'</h2>
		<form action="'.ft_get_self().'" method="post">
		<div>
		  <input type="radio" name="type" value="folder" id="type-folder" checked="checked" /> <label for="type-folder" class="label_highlight">'.t('Folder').'</label>
		  <input type="radio" name="type" value="file" id="type-file" /> <label for="type-file">'.t('File').'</label>
		  <input type="radio" name="type" value="url" id="type-url" /> <label for="type-url">'.t('From URL').'</label>
		</div>
			<div>
				<input type="text" name="newdir" id="newdir" size="16" />
				<input type="hidden" name="act" value="createdir" />
				<input type="hidden" name="dir" value="'.$_REQUEST['dir'].'" />
				<input type="submit" id="mkdirsubmit" name="submit" value="'.t('Ok').'" />
			</div>
		</form>
	</div>';
	}
  $sidebar = array();
  $result = ft_invoke_hook('sidebar');
  $sidebar = array_merge($sidebar, $result);
  
  if (is_array($sidebar)) {
    foreach ($sidebar as $c) {
      $str .= $c['content'];
    }
  }
	$str .= '</div>';
	return $str;
}

/**
 * Check if a plugin has been loaded.
 *
 * @param $plugin
 *   Name of the plugin to test.
 * @return TRUE if plugin is loaded.
 */
function ft_plugin_exists($plugin) {
  global $ft;
  foreach ($ft['loaded_plugins'] as $k => $v) {
    if ($v == $plugin) {
      return TRUE;
    }
  }
  return FALSE;
}

/**
 * Get a list of available plugins.
 */
function ft_plugins_list() {
  $plugin_list = array();
  // Get all files in the plugin dir.
	if ($dirlink = @opendir(PLUGINDIR)) {
		while (($file = readdir($dirlink)) !== false) {
		  // Only grab files that end in .plugin.php
			if (strstr($file, '.plugin.php')) {
			  // Load plugin files if they're not already there.
        $name = substr($file, 0, strpos($file, '.'));
        if (!ft_plugin_exists($name)) {
          include_once(PLUGINDIR.'/'.$file);
        }
        // Get plugin info. We can't use ft_invoke_hook since we need to loop through all plugins, not just the loaded plugins.
        if (function_exists('ft_'.$name.'_info')) {
          $plugin_list[$name] = call_user_func('ft_'.$name.'_info');
        } else {
          // If there's no info hook, we at least create some basic info.
          $plugin_list[$name] = array('name' => $name);
        }
			}
		}
	}
  return $plugin_list;
}

/**
 * Load plugins found in the current settings.
 */
function ft_plugins_load() {
  global $ft;
  $core = array('search', 'edit', 'tinymce');
  $ft['loaded_plugins'] = array();
  if (isset($ft['plugins']) && is_array($ft['plugins'])) {
    foreach ($ft['plugins'] as $name => $v) {
      // Include plugin file. We only need to load core modules if the install type is expanded.
      if (!in_array($name, $core) || (in_array($name, $core) && INSTALL != 'SIMPLE')) {
        // Not a core plugin or we're in expanded mode. Load file.
        if (file_exists(PLUGINDIR.'/'.$name.'.plugin.php')) {
          @include_once(PLUGINDIR.'/'.$name.'.plugin.php');
          $ft['loaded_plugins'][] = $name;
        } else {
          ft_set_message(t('Could not load !name plugin. File not found.', array('!name' => $name)), 'error');
        }
      } elseif (in_array($name, $core) && INSTALL == 'SIMPLE') {
        // Core plugin and we're in simple mode. Plugin file is already loaded.
        $ft['loaded_plugins'][] = $name;
      }
    }
  }
}

/**
 * Remove a plugin that has been loaded.
 *
 * @param $plugin
 *   Name of the plugin to remove.
 */
function ft_plugin_unload($plugin) {
  global $ft;
  foreach ($ft['loaded_plugins'] as $k => $v) {
    if ($v == $plugin) {
      unset($ft['loaded_plugins'][$k]);        
    }
  }
}

/**
 * Recursively remove a directory.
 */
function ft_rmdir_recurse($path) {
  $path= rtrim($path, '/').'/';
  $handle = opendir($path);
  for (;false !== ($file = readdir($handle));) {
    if($file != "." and $file != ".." ) {
      $fullpath = $path.$file;
      if(is_dir($fullpath)) {
        ft_rmdir_recurse($fullpath);
        if (!@rmdir($fullpath)) {
          return FALSE;
        }
      }
      else {
        if(!@unlink($fullpath)) {
          return FALSE;
        }
      }
    }
  }
  closedir($handle);
}

/**
 * Redirect to a File Thingie page.
 *
 * @param $query
 *   Query string to append to redirect.
 */
function ft_redirect($query = '') {
  if (REQUEST_URI) {
    $_SERVER['REQUEST_URI'] = REQUEST_URI;
  }
  $protocol = 'http://';
  if (HTTPS) {
    $protocol = 'https://';    
  }
  if (isset($_SERVER['REQUEST_URI'])) { 
  	if (stristr($_SERVER["REQUEST_URI"], "?")) {
  		$requesturi = substr($_SERVER["REQUEST_URI"], 0, strpos($_SERVER["REQUEST_URI"], "?"));
  		$location = "Location: {$protocol}{$_SERVER["HTTP_HOST"]}{$requesturi}";
  	} else {
  		$requesturi = $_SERVER["REQUEST_URI"];
  		$location = "Location: {$protocol}{$_SERVER["HTTP_HOST"]}{$requesturi}";
  	}
  } else { 
		$location = "Location: {$protocol}{$_SERVER["HTTP_HOST"]}{$_SERVER['PHP_SELF']}";
  }
	if (!empty($query)) {
		$location .= "?{$query}";
	}
	header($location);
	exit;
}

/**
 * Clean user input in $_REQUEST.
 */
function ft_sanitize_request() {
  // Kill null bytes
  foreach ($_REQUEST as $k => $v) {
    $_REQUEST[$k] = str_replace("\0", 'NULL', $_REQUEST[$k]);
    $_REQUEST[$k] = str_replace(chr(0), 'NULL', $_REQUEST[$k]);
  }
  if ($_FILES && is_array($_FILES)) {
    foreach ($_FILES as $k => $v) {
      $_FILES[$k]['name'] = str_replace("\0", 'NULL', $_FILES[$k]['name']);
      $_FILES[$k]['name'] = str_replace(chr(0), 'NULL', $_FILES[$k]['name']);
      $_FILES[$k]['name'] = urldecode($_FILES[$k]['name']);
      $_FILES[$k]['name'] = str_replace("&#00", 'NULL', $_FILES[$k]['name']);
    }
  }
  
	// Make sure 'dir' cannot be changed to open directories outside the stated FT directory.
	if (!empty($_REQUEST['dir']) && strstr($_REQUEST['dir'], "..") || !empty($_REQUEST['dir']) && strstr($_REQUEST['dir'], "./") || empty($_REQUEST['dir'])) {
		unset($_REQUEST['dir']);
	}
	// Set 'dir' to empty if it isn't set.
	if (!isset($_REQUEST['dir']) || empty($_REQUEST['dir'])) {
		$_REQUEST['dir'] = "";
	}
	// If 'dir' is set to just / it is a security risk.
	if (trim($_REQUEST['dir']) == '/') {
	  unset($_REQUEST['dir']);
  }
	// Nuke slashes from 'file' and 'newvalue'
	if (!empty($_REQUEST['file'])) {
		$_REQUEST['file'] = trim(str_replace("/", "", $_REQUEST['file']));
	}
	if (!empty($_REQUEST['act']) && $_REQUEST['act'] != "move") {
		if (!empty($_REQUEST['newvalue'])) {
			$_REQUEST['newvalue'] = str_replace("/", "", $_REQUEST['newvalue']);
			// Nuke ../ for 'newvalue' when not moving files.
			if (stristr($_REQUEST['newvalue'], "..") || empty($_REQUEST['newvalue'])) {
				unset($_REQUEST['newvalue']);
			}
		}
	}
	// Nuke ../ for 'file' and newdir
	if (!empty($_REQUEST['file']) && stristr($_REQUEST['file'], "..") || empty($_REQUEST['file'])) {
		unset($_REQUEST['file']);
	}
	if (!empty($_POST['newdir']) && stristr($_POST['newdir'], "..") || empty($_POST['newdir'])) {
		unset($_POST['newdir']);
	}
	// Set 'q' (search queries) to empty if it isn't set.
	if (empty($_REQUEST['q'])) {
		$_REQUEST['q'] = "";
	}
}

/**
 * Set status message for display.
 *
 * @param $message
 *   Message string to display.
 * @param $type
 *   Message type. Possible values: ok, error. Default is 'ok'.
 */
function ft_set_message($message = NULL, $type = 'ok') {
  if ($message) {
    if (!isset($_SESSION['ft_status'])) {
      $_SESSION['ft_status'] = array();
    }
    if (!isset($_SESSION['ft_status'][$type])) {
      $_SESSION['ft_status'][$type] = array();
    }
    $_SESSION['ft_status'][$type][] = $message;    
  }
}

/**
 * Load external configuration file.
 *
 * @param $file
 *   Path to external file to load.
 * @return Array of settings, users, groups and plugins.
 */
function ft_settings_external($file) {
  if (file_exists($file)) {
    @include_once($file);
    $json = ft_settings_external_load();
    if (!$json) {
      // Not translateable. Language info is not available yet.
      ft_set_message('Could not load external configuration.', 'error');
      return FALSE;      
    }
    return $json;
  }
  return FALSE;
}

/**
 * Prepare settings. Loads configuration file is any and
 * sets the needed setting constants according to user group.
 */
function ft_settings_load() {
  global $ft;
  $settings = array();
  
  // Load external configuration if any.
  $json = ft_settings_external('ft_config.php');
  if ($json) {
    // Merge settings.
    if (is_array($json['settings'])) {
      foreach ($json['settings'] as $k => $v) {
        $ft['settings'][$k] = $v;
      }
    }
    // Merge users.
    if (is_array($json['users'])) {
      foreach ($json['users'] as $k => $v) {
        $ft['users'][$k] = $v;
      }
    }
    // Merge groups.
    if (is_array($json['groups'])) {
      foreach ($json['groups'] as $k => $v) {
        $ft['groups'][$k] = $v;
      }
    }
    // Overwrite plugins
    if (is_array($json['plugins'])) {
      $ft['plugins'] = $json['plugins'];
      // foreach ($json['plugins'] as $k => $v) {
      //   $ft['plugins'][$k] = $v;
      // }
    }
  }
  
  // Save default settings before groups overwrite them.
  $ft['default_settings'] = $ft['settings'];
  
  // Check if current user is a member of a group.
  $current_group = FALSE;
  $current_group_name = FALSE;
  if (
    !empty($_SESSION['ft_user_'.MUTEX]) && 
    is_array($ft['groups']) && 
    is_array($ft['users']) && 
    array_key_exists($_SESSION['ft_user_'.MUTEX], $ft['users']) && 
    isset($ft['groups'][$ft['users'][$_SESSION['ft_user_'.MUTEX]]['group']]) &&
    is_array($ft['groups'][$ft['users'][$_SESSION['ft_user_'.MUTEX]]['group']])) {
      $current_group = $ft['groups'][$ft['users'][$_SESSION['ft_user_'.MUTEX]]['group']];
      // $current_group_name = $ft['users'][$_SESSION['ft_user_'.MUTEX]]['group'];
  }

  // Break out plugins in the group settings.
  if (is_array($current_group) && array_key_exists('plugins', $current_group)) {
    $ft['plugins'] = $current_group['plugins'];
    unset($current_group['plugins']);
  }
  
  // Loop through settings. Use group values if set.
  // foreach ($constants as $k => $v) {
  foreach ($ft['settings'] as $k => $v) {
    // $new_k = substr($k, 1);
    $new_k = $k;
    if (is_array($current_group) && array_key_exists($k, $current_group)) {
      // define($new_k, $current_group[$k]);
      $settings[$new_k] = $current_group[$k];
    } else {
      // Use original value.
      // define($new_k, $v);
      $settings[$new_k] = $v;
    }
  }
  // Define constants.
  $settings = ft_clean_settings($settings);
  foreach ($settings as $k => $v) {
    define($k, $v);    
  }
  // Clean up $ft.
  unset($ft['settings']);
}

/**
 * Strips slashes from string if magic quotes are on.
 *
 * @param $string
 *   String to filter.
 * @return The filtered string.
 */
function ft_stripslashes($string) {
  if (get_magic_quotes_gpc()) {
    return stripslashes($string);
  } else {
    return $string;
  }
}

/**
 * Translate a string to the current locale.
 *
 * @param $msg
 *   A string to be translated.
 * @param $vars
 *   An associative array of replacements for placeholders.
 *   Array keys in $msg will be replaced with array values.
 * @param $js
 *   Boolean indicating if return values should be escaped for JavaScript.
 *   Defaults to FALSE.
 * @return The translated string.
 */
function t($msg, $vars = array(), $js = FALSE) {
  global $ft_messages;
  if(isset($ft_messages[LANG]) && isset($ft_messages[LANG][$msg])) {
   $msg = $ft_messages[LANG][$msg];
  } else {
   $msg = $msg;      
  }
  // Replace vars
  if (count($vars) > 0) {
    foreach ($vars as $k => $v) {
      $msg = str_replace($k, $v, $msg);
    }
  }
  if ($js) {
    return str_replace("'", "\'", $msg);
  }
  return $msg;
}

# Plugins #


/**
 * @file
 * TinyMCE plugin for File Thingie.
 * Author: Andreas Haugstrup Pedersen, Copyright 2008, All Rights Reserved
 *
 * Must be loaded after the edit plugin.
 */

/**
 * Implementation of hook_info.
 */
function ft_tinymce_info() {
  return array(
    'name' => 'TinyMCE: Edit files using the TinyMCE editor.',
    'settings' => array(
      'list' => array(
        'default' => 'html htm',
        'description' => t('List of file extensions to edit using tinymce.'),
      ),
      'path' => array(
        'default' => 'tinymce/jscripts/tiny_mce/tiny_mce.js',
        'description' => t('Path to tiny_mce.js'),
      ),
    ),
  );
}

/**
 * Implementation of hook_add_js_file.
 */
function ft_tinymce_add_js_file() {
  global $ft;
  $return = array();
  // Only add JS when we are on an edit page.
  if (!empty($_REQUEST['act']) && $_REQUEST['act'] == 'edit' && file_exists($ft['plugins']['tinymce']['settings']['path'])) {
    $return[] = $ft['plugins']['tinymce']['settings']['path'];
  }
  return $return;
}

/**
 * Implementation of hook_add_js_call.
 */
function ft_tinymce_add_js_call() {
  global $ft;
  $return = '';
  // Only add JS when we're on an edit page.
  if (!empty($_REQUEST['act']) && $_REQUEST['act'] == 'edit' && file_exists($ft['plugins']['tinymce']['settings']['path'])) {
    $list = explode(" ", $ft['plugins']['tinymce']['settings']['list']);
    if (in_array(ft_get_ext(strtolower($_REQUEST['file'])), $list)) {
    	// Unbind save action and rebind with a tinymce specific version.
    	$return .= '$("#save").unbind();$("#save").click(function(){
  			$("#savestatus").empty().append("<p class=\"ok\">'.t('Saving file&hellip;').'</p>");
  			// Get file content from tinymce.
  			filecontent = tinyMCE.activeEditor.getContent();
  			$.post("'.ft_get_self().'", {method:\'ajax\', act:\'saveedit\', file: $(\'#file\').val(), dir: $(\'#dir\').val(), filecontent: filecontent}, function(data){
  				$("#savestatus").empty().append(data);
  			});
  		});';
    }
  }
  return $return;
}

/**
 * Implementation of hook_add_js_call_footer.
 */
function ft_tinymce_add_js_call_footer() {
  global $ft;
  $return = '';
  // Only add JS when we're on an edit page.
  if (!empty($_REQUEST['act']) && $_REQUEST['act'] == 'edit') {
    if (file_exists($ft['plugins']['tinymce']['settings']['path'])) {
      $list = explode(" ", $ft['plugins']['tinymce']['settings']['list']);
      if (in_array(ft_get_ext(strtolower($_REQUEST['file'])), $list)) {
        $return = 'tinyMCE.init({
          mode : "exact",
          elements : "filecontent",
          theme : "advanced",
          theme_advanced_toolbar_location : "top",
          theme_advanced_toolbar_align : "left"
        });';
      } else {
        $return = '// File not in TinyMCE edit list.';
      }
    } else {
      $return = '// TinyMCE file not found: ' . $ft['plugins']['tinymce']['settings']['path'];
    }
  }
  return $return;
}




/**
 * @file
 * Edit file plugin for File Thingie.
 * Author: Andreas Haugstrup Pedersen, Copyright 2008, All Rights Reserved
 *
 * Must be loaded after the db plugin if file locking is to be used.
 */

/**
 * Implementation of hook_info.
 */
function ft_edit_info() {
  return array(
    'name' => 'Edit: Enabling editing of text-based files.',
    'settings' => array(
      'editlist' => array(
        'default' => 'txt html htm css',
        'description' => t('List of file extensions to edit.'),
      ),
      'converttabs' => array(
        'default' => FALSE,
        'description' => t('Convert tabs to spaces'),
      ),
    ),
  );
}

/**
 * Implementation of hook_init.
 */
function ft_edit_init() {
  global $ft;
  // Check if DB plugin is loaded.
  // if (ft_plugin_exists('db')) {
  //   // Check if we need to create new table.
  //   $sql = "CREATE TABLE edit (
  //     dir TEXT NOT NULL,
  //     file TEXT NOT NULL,
  //     user TEXT NOT NULL,
  //     timestamp INTEGER
  //   )";
  //   ft_db_install_table('edit', $sql);    
  // }
}

/**
 * Implementation of hook_page.
 */
function ft_edit_page($act) {
  global $ft;
  $str = '';
  if ($act == 'edit') {
		$_REQUEST['file'] = trim(ft_stripslashes($_REQUEST['file']));
		$str = "<h2>".t('Edit file:')." {$_REQUEST['file']}</h2>";
		// Check that file exists and that it's writeable.
		if (is_writeable(ft_get_dir()."/".$_REQUEST['file'])) {
			// Check that filetype is editable.
			if (ft_check_dir(ft_get_dir()) && ft_check_edit($_REQUEST['file']) && ft_check_fileactions() === TRUE && ft_check_filetype($_REQUEST['file']) && ft_check_filetype($_REQUEST['file'])) {
				// Get file contents.
				$filecontent = implode ("", file(ft_get_dir()."/{$_REQUEST["file"]}"));
				$filecontent = htmlspecialchars($filecontent);
				if ($ft['plugins']['edit']['settings']['converttabs'] == TRUE) {
					$filecontent = str_replace("\t", "    ", $filecontent);
				}
				$lock = FALSE;
				// Lock file if db plugin is loaded.
				$lock = ft_edit_lock_get($_REQUEST["file"], ft_get_dir());
        if ($lock !== FALSE) {
          if ($lock === $_SESSION['ft_user_'.MUTEX]) {
            // File is in use by current user. Quietly update lock.
            // $str .= '<p class="ok">'.t('You are already editing this file.').'</p>';
            $lock = FALSE;
          }
        }
				if ($lock === FALSE) {
				  // File is not locked. Set a new lock for the current user.
  				ft_edit_lock_set($_REQUEST["file"], ft_get_dir(), $_SESSION['ft_user_'.MUTEX]);
				  // Make form or show lock message.
  				$str .= '<form id="edit" action="'.ft_get_self().'" method="post">
  					<div>
  						<textarea cols="76" rows="20" name="filecontent" id="filecontent">'.$filecontent.'</textarea>
  					</div>
  					<div>
  						<input type="hidden" name="file" id="file" value="'.$_REQUEST['file'].'" />
  						<input type="hidden" name="dir" id="dir" value="'.$_REQUEST['dir'].'" />
  						<input type="hidden" name="act" value="savefile" />
              <button type="button" id="save">'.t('Save').'</button>
  						<input type="submit" value="'.t('Save &amp; exit').'" name="submit" />
  						<input type="submit" value="'.t('Cancel').'" name="submit" />
    					<div id="savestatus"></div>
  					</div>
  				</form>';				  
				} else {
				  $str .= '<p class="error">'.t('Cannot edit file. This file is currently being edited by !name', array('!name' => $lock)).'</p>';				    
				}
			} else {
				$str .= '<p class="error">'.t('Cannot edit file. This file type is not editable.').'</p>';				
			}
		} else {
			$str .= '<p class="error">'.t('Cannot edit file. It either does not exist or is not writeable.').'</p>';
		}
  }
  return $str;
}

/**
 * Implementation of hook_fileextras.
 */
function ft_edit_fileextras($file, $dir) {
  if (ft_check_edit($file) && !is_dir("{$dir}/{$file}")) {
		return 'edit';
	}
  return FALSE;
}

/**
 * Implementation of hook_action.
 */
function ft_edit_action($act) {
  global $ft;
  if ($act == 'savefile') {
		$file = trim(ft_stripslashes($_REQUEST["file"]));
    if (ft_check_fileactions() === TRUE) {
			// Save a file that has been edited.
			// Delete any locks on this file.
			ft_edit_lock_clear($file, ft_get_dir());
			// Check for edit or cancel
			if (strtolower($_REQUEST["submit"]) != strtolower(t("Cancel"))) {        
				// Check if file type can be edited.
				if (ft_check_dir(ft_get_dir()) && ft_check_edit($file) && ft_check_fileactions() === TRUE && ft_check_filetype($file) && ft_check_filetype($file)) {
					$filecontent = ft_stripslashes($_REQUEST["filecontent"]);
					/*if ($_REQUEST["convertspaces"] != "") {
						$filecontent = str_replace("    ", "\t", $filecontent);
					}*/
					if (is_writeable(ft_get_dir()."/{$file}")) {
						$fp = @fopen(ft_get_dir()."/{$file}", "wb");
						if ($fp) {
							fputs ($fp, $filecontent);
							fclose($fp);
							ft_set_message(t("!old was saved.", array('!old' => $file)));
							ft_redirect("dir={$_REQUEST['dir']}");
						} else {
							ft_set_message(t("!old could not be edited.", array('!old' => $file)), 'error');
							ft_redirect("dir={$_REQUEST['dir']}");
						}
					} else {
						ft_set_message(t("!old could not be edited.", array('!old' => $file)), 'error');
						ft_redirect("dir={$_REQUEST['dir']}");
					}
				} else {
					ft_set_message(t("Could not edit file. This file type is not editable."), 'error');
					ft_redirect("dir={$_REQUEST['dir']}");
				}
			} else {
				ft_redirect("dir=".rawurlencode($_REQUEST['dir']));
			}
		}
  }
}

/**
 * Implementation of hook_ajax.
 */
function ft_edit_ajax($act) {
  if ($act == 'saveedit') {
		// Do save file.
		$file = trim(ft_stripslashes($_POST["file"]));
		// Check if file type can be edited.
		if (ft_check_dir(ft_get_dir()) && ft_check_edit($file) && ft_check_fileactions() === TRUE && ft_check_filetype($file) && ft_check_filetype($file)) {
			$filecontent = ft_stripslashes($_POST["filecontent"]);
			/*if ($_POST["convertspaces"] != "") {
				$filecontent = str_replace("    ", "\t", $filecontent);
			}*/
			if (is_writeable(ft_get_dir()."/{$file}")) {
				$fp = @fopen(ft_get_dir()."/{$file}", "wb");
				if ($fp) {
					fputs ($fp, $filecontent);
					fclose($fp);
          // edit
          echo '<p class="ok">' . t("!old was saved.", array('!old' => $file)) . '</p>';
				} else {
				  // editfilefail
				  echo '<p class="error">' . t("!old could not be edited.", array('!old' => $file)) . '</p>';
				}
			} else {
        // editfilefail
        echo '<p class="error">' . t("!old could not be edited.", array('!old' => $file)) . '</p>';
			}
		} else {
      // edittypefail
      echo '<p class="error">' . t("Could not edit file. This file type is not editable.") . '</p>';
		}
  } elseif ($act == 'edit_get_lock') {
    ft_edit_lock_set($_POST['file'], $_POST['dir'], $_SESSION['ft_user_'.MUTEX]);
    echo 'File locked.';
  }
}

/**
 * Implementation of hook_add_js_call.
 */
function ft_edit_add_js_call() {
  $return = '';
  // Save via ajax (opposed to save & exit)
  if (!empty($_REQUEST['act']) && $_REQUEST['act'] == 'edit') {
    $return .= '$("#save").click(function(){
  	$("#savestatus").empty().append("<p class=\"ok\">'.t('Saving file&hellip;').'</p>");
  	$.post("'.ft_get_self().'", {method:\'ajax\', act:\'saveedit\', file: $(\'#file\').val(), dir: $(\'#dir\').val(), filecontent: $(\'#filecontent\').val()}, function(data){
  		$("#savestatus").empty().append(data);
  	});
  });';
  // Heartbeat to keep file locked.
  $return .= 'ft.edit_beat = function(){
    $.post("'.ft_get_self().'", {method:\'ajax\', act:\'edit_get_lock\', file: $(\'#file\').val(), dir: $(\'#dir\').val()}, function(data){
  	});
  };
  ft.edit_heartbeat = setInterval(function() {
    // Make ajax call to make sure file stays locked.
    ft.edit_beat();
  }, 30000);';
  } else {
    $return = 'ft.fileactions.edit = {type: "sendoff", link: "'.t('Edit').'", text: "'.t('Do you want to edit this file?').'", button: "'.t('Yes, edit file').'"};';
  }
  return $return;
}

/**
 * Check if file is on the edit list.
 *
 * @param $file
 *   File name.
 * @return TRUE if file is on the edit list.
 */
function ft_check_edit($file) {
  global $ft;
	// Check against file blacklist.
	if ($ft['plugins']['edit']['settings']['editlist'] != "") {
		$list = explode(" ", $ft['plugins']['edit']['settings']['editlist']);
		if (in_array(ft_get_ext(strtolower($file)), $list)) {
			return TRUE;
		} else {
			return FALSE;
		}
	} else {
		return FALSE;
	}
}

/**
 * Clear a lock on a file.
 *
 * @param $file
 *   File name to clear.
 * @param $dir
 *   Directory where file resides.
 */
function ft_edit_lock_clear($file, $dir) {
  global $ft;
  // if (ft_plugin_exists('db')) {
  //   $sql = "DELETE FROM edit WHERE dir = '".sqlite_escape_string($dir)."' AND file = '".sqlite_escape_string($file)."'";
  //   sqlite_query($ft['db']['link'], $sql);
  // }
}

/**
 * Get a lock status on a file.
 *
 * @param $file
 *   File name to clear.
 * @param $dir
 *   Directory where file resides.
 * @return Username if the file has a lock. FALSE if it doesn't.
 */
function ft_edit_lock_get($file, $dir) {
  global $ft;
  // if (ft_plugin_exists('db')) {
  //   // See if file has been locked.
  //   $sql = "SELECT user, timestamp FROM edit WHERE dir = '".sqlite_escape_string($dir)."' AND file = '".sqlite_escape_string($file)."' ORDER BY timestamp DESC";
  //   $result = sqlite_query($ft['db']['link'], $sql);
  //   if ($result) {
  //     if (sqlite_num_rows($result) > 0) {
  //       $user = sqlite_fetch_array($result);
  //       // Check timestamp. Locks expire after 2 minutes.
  //       if ($user['timestamp'] < time()-120) {
  //         // Lock has expired. Clear it.
  //         ft_edit_lock_clear($file, $dir);
  //         return FALSE;
  //       } else {
  //         // Someone is already editing this.
  //         return $user['user'];
  //       }
  //     } else {
  //       return FALSE;
  //     }
  //   }
  // }
  return FALSE;
}

/**
 * Set a lock on a file.
 *
 * @param $file
 *   File name to clear.
 * @param $dir
 *   Directory where file resides.
 * @param $user
 *   Username of the user to lock the file for.
 */
function ft_edit_lock_set($file, $dir, $user) {
  global $ft;
  // if (ft_plugin_exists('db')) {
  //   // Clear any locks.
  //   ft_edit_lock_clear($file, $dir);
  //   // Set new lock.
  //   $sql = "INSERT INTO edit (dir, file, user, timestamp) VALUES ('" . sqlite_escape_string($dir) . "','" . sqlite_escape_string($file) . "','" . sqlite_escape_string($user) . "'," . time() . ")";
  //   sqlite_query($ft['db']['link'], $sql);              
  // }
}


/**
 * @file
 * Search plugin for File Thingie.
 * Author: Andreas Haugstrup Pedersen, Copyright 2008, All Rights Reserved
 */

/**
 * Implementation of hook_info.
 */
function ft_search_info() {
  return array(
    'name' => 'Search: Search files and folders.',
  );
}

/**
 * Implementation of hook_sidebar.
 */
function ft_search_sidebar() {
  $sidebar[] = array(
    "id" => "search_1",
    "content" => '<div class="section">
  		<h2>'.t('Search files &amp; folders').'</h2>
  		<form action="" method="post" id="searchform">
  			<div>
  				<input type="text" name="q" id="q" size="16" value="'.$_REQUEST['q'].'" />
  				<input type="button" id="dosearch" value="'.t('Search').'" />
  			</div>
  			<div id="searchoptions">
  				<input type="checkbox" name="type" id="type" checked="checked" /> <label for="type">'.t('Search only this folder and below').'</label>
  			</div>
  			<div id="searchresults"></div>
  		</form>
  	</div>'
  );
  return $sidebar;
}

/**
 * Implementation of hook_ajax.
 */
function ft_search_ajax($act) {
  if ($act == 'search') {
    $new = array();
  	$ret = "";
  	$q = $_POST['q'];
  	$type = $_POST['type'];
  	if (!empty($q)) {
  		if ($type == "true") {
  			$list = _ft_search_find_files(ft_get_dir(), $q);
  		} else {
  			$list = _ft_search_find_files(ft_get_root(), $q);
  		}
  		if (is_array($list)){
  			if (count($list) > 0) {
  				foreach ($list as $c) {
  					if (empty($c['dir'])) {
  						$c['dirlink'] = "/";
  					} else {
  						$c['dirlink'] = $c['dir'];
  					}
  					if ($c['type'] == "file") {
  					  $link = "<a href='".ft_get_root()."{$c['dir']}/{$c['name']}' title='" .t('Show !file', array('!file' => $c['name'])). "'>{$c['shortname']}</a>";
  					  if (HIDEFILEPATHS == TRUE) {
  					    $link = ft_make_link($c['shortname'], 'method=getfile&amp;dir='.rawurlencode($c['dir']).'&amp;file='.$c['name'], t('Show !file', array('!file' => $c['name'])));
  					  }
  						$ret .= "<dt>{$link}</dt><dd>".ft_make_link($c['dirlink'], "dir=".rawurlencode($c['dir'])."&amp;highlight=".rawurlencode($c['name'])."&amp;q=".rawurlencode($q), t("Highlight file in directory"))."</dd>";
  					} else {
  						$ret .= "<dt class='dir'>".ft_make_link($c['shortname'], "dir=".rawurlencode("{$c['dir']}/{$c['name']}")."&amp;q={$q}", t("Show files in !folder", array('!folder' => $c['name'])))."</dt><dd>".ft_make_link($c['dirlink'], "dir=".rawurlencode($c['dir'])."&amp;highlight=".rawurlencode($c['name'])."&amp;q=".rawurlencode($q), t("Highlight file in directory"))."</dd>";
  					}
  				}
  				return $ret;
  			} else {
  				return "<dt class='error'>".t('No files found').".</dt>";
  			}
  		} else {
  			return "<dt class='error'>".t('Error.')."</dt>";
  		}
  	} else {
  		return "<dt class='error'>".t('Enter a search string.')."</dt>";		
  	}
  }
}

/**
 * Implementation of hook_add_js_call.
 */
function ft_search_add_js_call() {
  $return = '';
  $return .= "$('#searchform').ft_search({\r\n";
  if (!empty($_REQUEST['dir'])) {
    $return .= "\tdirectory: '{$_REQUEST['dir']}',\r\n";
  } else {
    $return .= "\tdirectory: '',\r\n";
  }
  $return .= "\tformpost: '".ft_get_self()."',\r\n";
  $return .= "\theader: '".t('Results')."',\r\n";
  $return .= "\tloading: '".t('Fetching results&hellip;')."'\r\n";
  $return .= '});';
  return $return;
}

/**
 * Private function. Searches for file names and directories recursively.
 *
 * @param $dir
 *   Directory to search.
 * @param $q
 *   Search query.
 * @return An array of files. Each item is an array:
 *   array(
 *     'name' => '', // File name.
 *     'shortname' => '', // File name.
 *     'type' => '', // 'file' or 'dir'.
 *     'dir' => '', // Directory where file is located.
 *   )
 */
function _ft_search_find_files($dir, $q){
	$output = array();
	if (ft_check_dir($dir) && $dirlink = @opendir($dir)) {
		while(($file = readdir($dirlink)) !== false){
			if($file != "." && $file != ".." && ((ft_check_file($file) && ft_check_filetype($file)) || (is_dir($dir."/".$file) && ft_check_dir($file)))){
				$path = $dir.'/'.$file;
				// Check if filename/directory name is a match.
				if(stristr($file, $q)) {
					$new['name'] = $file;
					$new['shortname'] = ft_get_nice_filename($file, 20);
					$new['dir'] = substr($dir, strlen(ft_get_root()));
					if (is_dir($path)) {
            if (ft_check_dir($path)) {
  						$new['type'] = "dir";					    
    					$output[] = $new;
            }
					} else {
					  $new['type'] = "file";
  					$output[] = $new;
					}
				}
				// Check subdirs for matches.
				if(is_dir($path)) {
					$dirres = _ft_search_find_files($path, $q);
					if (is_array($dirres) && count($dirres) > 0) {
						$output = array_merge($dirres, $output);
						unset($dirres);						
					}
				}
			}
		}
		sort($output);
		closedir($dirlink);
		return $output;
	} else {
		return FALSE;
	}
}


# Set timezone if PHP version is larger than 5.10. #
if (function_exists('date_default_timezone_set')) {
  date_default_timezone_set(date_default_timezone_get());
}

# Start running File Thingie #
// Check if headers has already been sent.
if (headers_sent()) {
  $str = ft_make_headers_failed();
} else {
  session_start();
  header("Content-Type: text/html; charset=UTF-8");
  header("Connection: close");
  // Prep settings
  ft_settings_load();
  // Load plugins
  ft_plugins_load();
  ft_invoke_hook('init');
  // Prep language.
  if (file_exists("ft_lang_".LANG.".php")) {
    @include_once("ft_lang_".LANG.".php");
  }
  // Only calculate total dir size if limit has been set.
  if (LIMIT > 0) {
  	define('ROOTDIRSIZE', ft_get_dirsize(ft_get_root()));  	  
  }

  $str = "";
  // Request is a file download.
  if (!empty($_GET['method']) && $_GET['method'] == 'getfile' && !empty($_GET['file'])) {
    if (ft_check_login()) {
      ft_sanitize_request();
      // Make sure we don't run out of time to send the file.
      @ignore_user_abort();
      @set_time_limit(0);
      @ini_set("zlib.output_compression", "Off");
      @session_write_close();
      // Open file for reading
      if(!$fdl=@fopen(ft_get_dir().'/'.$_GET['file'],'rb')){        
          die("Cannot Open File!");
      } else {
        ft_invoke_hook('download', ft_get_dir(), $_GET['file']);
        header("Cache-Control: ");// leave blank to avoid IE errors
        header("Pragma: ");// leave blank to avoid IE errors
        header("Content-type: application/octet-stream");
        header("Content-Disposition: attachment; filename=\"".htmlentities($_GET['file'])."\"");
        header("Content-length:".(string)(filesize(ft_get_dir().'/'.$_GET['file'])));
        header ("Connection: close");      
        sleep(1);
        fpassthru($fdl);
      }
    } else {
			// Authentication error.
      ft_redirect();
    }
    exit;
  } elseif (!empty($_POST['method']) && $_POST['method'] == "ajax") {
    // Request is an ajax request.
  	if (!empty($_POST['act']) && $_POST['act'] == "versioncheck") {
  		// Do version check
  		if (ft_check_login()) {
  			echo ft_check_version();
  		} else {
  			// Authentication error. Send 403.
  			header("HTTP/1.1 403 Forbidden");
  			echo "<p class='error'>".t('Login error.')."</p>";
  		}		
  	} else {
  		if (ft_check_login()) {
  			ft_sanitize_request();
  			// Run the ajax hook for modules implementing ajax.
  			echo implode('', ft_invoke_hook('ajax', $_POST['act']));
  		} else {
  			// Authentication error. Send 403.
  			header("HTTP/1.1 403 Forbidden");
  			echo "<dt class='error'>".t('Login error.')."</dt>";
  		}
  	}
  	exit;
  }
  if (ft_check_login()) {
  	// Run initializing functions.
  	ft_sanitize_request();
  	ft_do_action();
  	$str = ft_make_header();
  	$str .= ft_make_sidebar();
  	$str .= ft_make_body();
  } else {
    	$str .= ft_make_login();
  }
  $str .= ft_make_footer();
}
?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
	"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="<?php echo LANG;?>" lang="<?php echo LANG;?>">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<title>File Thingie <?php echo VERSION;?></title>
	<link rel="author" href="http://www.solitude.dk/" title="Andreas Haugstrup Pedersen" />
	<link rel="home" href="<?php echo ft_get_self();?>" title="<?php echo t('Go to home folder');?>" />
	<link rel="help" href="http://www.solitude.dk/filethingie/documentation" title="<?php echo t('Online documentation');?>" />

<script type="text/javascript" charset="utf-8">/*
 * jQuery 1.2.1 - New Wave Javascript
 *
 * Copyright (c) 2007 John Resig (jquery.com)
 * Dual licensed under the MIT (MIT-LICENSE.txt)
 * and GPL (GPL-LICENSE.txt) licenses.
 *
 * $Date: 2007-09-16 23:42:06 -0400 (Sun, 16 Sep 2007) $
 * $Rev: 3353 $
 */
eval(function(p,a,c,k,e,r){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('(G(){9(1m E!="W")H w=E;H E=18.15=G(a,b){I 6 7u E?6.5N(a,b):1u E(a,b)};9(1m $!="W")H D=$;18.$=E;H u=/^[^<]*(<(.|\\s)+>)[^>]*$|^#(\\w+)$/;E.1b=E.3A={5N:G(c,a){c=c||U;9(1m c=="1M"){H m=u.2S(c);9(m&&(m[1]||!a)){9(m[1])c=E.4D([m[1]],a);J{H b=U.3S(m[3]);9(b)9(b.22!=m[3])I E().1Y(c);J{6[0]=b;6.K=1;I 6}J c=[]}}J I 1u E(a).1Y(c)}J 9(E.1n(c))I 1u E(U)[E.1b.2d?"2d":"39"](c);I 6.6v(c.1c==1B&&c||(c.4c||c.K&&c!=18&&!c.1y&&c[0]!=W&&c[0].1y)&&E.2h(c)||[c])},4c:"1.2.1",7Y:G(){I 6.K},K:0,21:G(a){I a==W?E.2h(6):6[a]},2o:G(a){H b=E(a);b.4Y=6;I b},6v:G(a){6.K=0;1B.3A.1a.16(6,a);I 6},N:G(a,b){I E.N(6,a,b)},4I:G(a){H b=-1;6.N(G(i){9(6==a)b=i});I b},1x:G(f,d,e){H c=f;9(f.1c==3X)9(d==W)I 6.K&&E[e||"1x"](6[0],f)||W;J{c={};c[f]=d}I 6.N(G(a){L(H b 1i c)E.1x(e?6.R:6,b,E.1e(6,c[b],e,a,b))})},17:G(b,a){I 6.1x(b,a,"3C")},2g:G(e){9(1m e!="5i"&&e!=S)I 6.4n().3g(U.6F(e));H t="";E.N(e||6,G(){E.N(6.3j,G(){9(6.1y!=8)t+=6.1y!=1?6.6x:E.1b.2g([6])})});I t},5m:G(b){9(6[0])E(b,6[0].3H).6u().3d(6[0]).1X(G(){H a=6;1W(a.1w)a=a.1w;I a}).3g(6);I 6},8m:G(a){I 6.N(G(){E(6).6q().5m(a)})},8d:G(a){I 6.N(G(){E(6).5m(a)})},3g:G(){I 6.3z(1q,Q,1,G(a){6.58(a)})},6j:G(){I 6.3z(1q,Q,-1,G(a){6.3d(a,6.1w)})},6g:G(){I 6.3z(1q,P,1,G(a){6.12.3d(a,6)})},50:G(){I 6.3z(1q,P,-1,G(a){6.12.3d(a,6.2q)})},2D:G(){I 6.4Y||E([])},1Y:G(t){H b=E.1X(6,G(a){I E.1Y(t,a)});I 6.2o(/[^+>] [^+>]/.14(t)||t.1g("..")>-1?E.4V(b):b)},6u:G(e){H f=6.1X(G(){I 6.67?E(6.67)[0]:6.4R(Q)});H d=f.1Y("*").4O().N(G(){9(6[F]!=W)6[F]=S});9(e===Q)6.1Y("*").4O().N(G(i){H c=E.M(6,"2P");L(H a 1i c)L(H b 1i c[a])E.1j.1f(d[i],a,c[a][b],c[a][b].M)});I f},1E:G(t){I 6.2o(E.1n(t)&&E.2W(6,G(b,a){I t.16(b,[a])})||E.3m(t,6))},5V:G(t){I 6.2o(t.1c==3X&&E.3m(t,6,Q)||E.2W(6,G(a){I(t.1c==1B||t.4c)?E.2A(a,t)<0:a!=t}))},1f:G(t){I 6.2o(E.1R(6.21(),t.1c==3X?E(t).21():t.K!=W&&(!t.11||E.11(t,"2Y"))?t:[t]))},3t:G(a){I a?E.3m(a,6).K>0:P},7c:G(a){I 6.3t("."+a)},3i:G(b){9(b==W){9(6.K){H c=6[0];9(E.11(c,"24")){H e=c.4Z,a=[],Y=c.Y,2G=c.O=="24-2G";9(e<0)I S;L(H i=2G?e:0,33=2G?e+1:Y.K;i<33;i++){H d=Y[i];9(d.26){H b=E.V.1h&&!d.9V["1Q"].9L?d.2g:d.1Q;9(2G)I b;a.1a(b)}}I a}J I 6[0].1Q.1p(/\\r/g,"")}}J I 6.N(G(){9(b.1c==1B&&/4k|5j/.14(6.O))6.2Q=(E.2A(6.1Q,b)>=0||E.2A(6.2H,b)>=0);J 9(E.11(6,"24")){H a=b.1c==1B?b:[b];E("9h",6).N(G(){6.26=(E.2A(6.1Q,a)>=0||E.2A(6.2g,a)>=0)});9(!a.K)6.4Z=-1}J 6.1Q=b})},4o:G(a){I a==W?(6.K?6[0].3O:S):6.4n().3g(a)},6H:G(a){I 6.50(a).28()},6E:G(i){I 6.2J(i,i+1)},2J:G(){I 6.2o(1B.3A.2J.16(6,1q))},1X:G(b){I 6.2o(E.1X(6,G(a,i){I b.2O(a,i,a)}))},4O:G(){I 6.1f(6.4Y)},3z:G(f,d,g,e){H c=6.K>1,a;I 6.N(G(){9(!a){a=E.4D(f,6.3H);9(g<0)a.8U()}H b=6;9(d&&E.11(6,"1I")&&E.11(a[0],"4m"))b=6.4l("1K")[0]||6.58(U.5B("1K"));E.N(a,G(){H a=c?6.4R(Q):6;9(!5A(0,a))e.2O(b,a)})})}};G 5A(i,b){H a=E.11(b,"1J");9(a){9(b.3k)E.3G({1d:b.3k,3e:P,1V:"1J"});J E.5f(b.2g||b.6s||b.3O||"");9(b.12)b.12.3b(b)}J 9(b.1y==1)E("1J",b).N(5A);I a}E.1k=E.1b.1k=G(){H c=1q[0]||{},a=1,2c=1q.K,5e=P;9(c.1c==8o){5e=c;c=1q[1]||{}}9(2c==1){c=6;a=0}H b;L(;a<2c;a++)9((b=1q[a])!=S)L(H i 1i b){9(c==b[i])6r;9(5e&&1m b[i]==\'5i\'&&c[i])E.1k(c[i],b[i]);J 9(b[i]!=W)c[i]=b[i]}I c};H F="15"+(1u 3D()).3B(),6p=0,5c={};E.1k({8a:G(a){18.$=D;9(a)18.15=w;I E},1n:G(a){I!!a&&1m a!="1M"&&!a.11&&a.1c!=1B&&/G/i.14(a+"")},4a:G(a){I a.2V&&!a.1G||a.37&&a.3H&&!a.3H.1G},5f:G(a){a=E.36(a);9(a){9(18.6l)18.6l(a);J 9(E.V.1N)18.56(a,0);J 3w.2O(18,a)}},11:G(b,a){I b.11&&b.11.27()==a.27()},1L:{},M:G(c,d,b){c=c==18?5c:c;H a=c[F];9(!a)a=c[F]=++6p;9(d&&!E.1L[a])E.1L[a]={};9(b!=W)E.1L[a][d]=b;I d?E.1L[a][d]:a},30:G(c,b){c=c==18?5c:c;H a=c[F];9(b){9(E.1L[a]){2E E.1L[a][b];b="";L(b 1i E.1L[a])1T;9(!b)E.30(c)}}J{2a{2E c[F]}29(e){9(c.53)c.53(F)}2E E.1L[a]}},N:G(a,b,c){9(c){9(a.K==W)L(H i 1i a)b.16(a[i],c);J L(H i=0,48=a.K;i<48;i++)9(b.16(a[i],c)===P)1T}J{9(a.K==W)L(H i 1i a)b.2O(a[i],i,a[i]);J L(H i=0,48=a.K,3i=a[0];i<48&&b.2O(3i,i,3i)!==P;3i=a[++i]){}}I a},1e:G(c,b,d,e,a){9(E.1n(b))b=b.2O(c,[e]);H f=/z-?4I|7T-?7Q|1r|69|7P-?1H/i;I b&&b.1c==4W&&d=="3C"&&!f.14(a)?b+"2T":b},1o:{1f:G(b,c){E.N((c||"").2l(/\\s+/),G(i,a){9(!E.1o.3K(b.1o,a))b.1o+=(b.1o?" ":"")+a})},28:G(b,c){b.1o=c!=W?E.2W(b.1o.2l(/\\s+/),G(a){I!E.1o.3K(c,a)}).66(" "):""},3K:G(t,c){I E.2A(c,(t.1o||t).3s().2l(/\\s+/))>-1}},2k:G(e,o,f){L(H i 1i o){e.R["3r"+i]=e.R[i];e.R[i]=o[i]}f.16(e,[]);L(H i 1i o)e.R[i]=e.R["3r"+i]},17:G(e,p){9(p=="1H"||p=="2N"){H b={},42,41,d=["7J","7I","7G","7F"];E.N(d,G(){b["7C"+6]=0;b["7B"+6+"5Z"]=0});E.2k(e,b,G(){9(E(e).3t(\':3R\')){42=e.7A;41=e.7w}J{e=E(e.4R(Q)).1Y(":4k").5W("2Q").2D().17({4C:"1P",2X:"4F",19:"2Z",7o:"0",1S:"0"}).5R(e.12)[0];H a=E.17(e.12,"2X")||"3V";9(a=="3V")e.12.R.2X="7g";42=e.7e;41=e.7b;9(a=="3V")e.12.R.2X="3V";e.12.3b(e)}});I p=="1H"?42:41}I E.3C(e,p)},3C:G(h,j,i){H g,2w=[],2k=[];G 3n(a){9(!E.V.1N)I P;H b=U.3o.3Z(a,S);I!b||b.4y("3n")==""}9(j=="1r"&&E.V.1h){g=E.1x(h.R,"1r");I g==""?"1":g}9(j.1t(/4u/i))j=y;9(!i&&h.R[j])g=h.R[j];J 9(U.3o&&U.3o.3Z){9(j.1t(/4u/i))j="4u";j=j.1p(/([A-Z])/g,"-$1").2p();H d=U.3o.3Z(h,S);9(d&&!3n(h))g=d.4y(j);J{L(H a=h;a&&3n(a);a=a.12)2w.4w(a);L(a=0;a<2w.K;a++)9(3n(2w[a])){2k[a]=2w[a].R.19;2w[a].R.19="2Z"}g=j=="19"&&2k[2w.K-1]!=S?"2s":U.3o.3Z(h,S).4y(j)||"";L(a=0;a<2k.K;a++)9(2k[a]!=S)2w[a].R.19=2k[a]}9(j=="1r"&&g=="")g="1"}J 9(h.3Q){H f=j.1p(/\\-(\\w)/g,G(m,c){I c.27()});g=h.3Q[j]||h.3Q[f];9(!/^\\d+(2T)?$/i.14(g)&&/^\\d/.14(g)){H k=h.R.1S;H e=h.4v.1S;h.4v.1S=h.3Q.1S;h.R.1S=g||0;g=h.R.71+"2T";h.R.1S=k;h.4v.1S=e}}I g},4D:G(a,e){H r=[];e=e||U;E.N(a,G(i,d){9(!d)I;9(d.1c==4W)d=d.3s();9(1m d=="1M"){d=d.1p(/(<(\\w+)[^>]*?)\\/>/g,G(m,a,b){I b.1t(/^(70|6Z|6Y|9Q|4t|9N|9K|3a|9G|9E)$/i)?m:a+"></"+b+">"});H s=E.36(d).2p(),1s=e.5B("1s"),2x=[];H c=!s.1g("<9y")&&[1,"<24>","</24>"]||!s.1g("<9w")&&[1,"<6T>","</6T>"]||s.1t(/^<(9u|1K|9t|9r|9p)/)&&[1,"<1I>","</1I>"]||!s.1g("<4m")&&[2,"<1I><1K>","</1K></1I>"]||(!s.1g("<9m")||!s.1g("<9k"))&&[3,"<1I><1K><4m>","</4m></1K></1I>"]||!s.1g("<6Y")&&[2,"<1I><1K></1K><6L>","</6L></1I>"]||E.V.1h&&[1,"1s<1s>","</1s>"]||[0,"",""];1s.3O=c[1]+d+c[2];1W(c[0]--)1s=1s.5p;9(E.V.1h){9(!s.1g("<1I")&&s.1g("<1K")<0)2x=1s.1w&&1s.1w.3j;J 9(c[1]=="<1I>"&&s.1g("<1K")<0)2x=1s.3j;L(H n=2x.K-1;n>=0;--n)9(E.11(2x[n],"1K")&&!2x[n].3j.K)2x[n].12.3b(2x[n]);9(/^\\s/.14(d))1s.3d(e.6F(d.1t(/^\\s*/)[0]),1s.1w)}d=E.2h(1s.3j)}9(0===d.K&&(!E.11(d,"2Y")&&!E.11(d,"24")))I;9(d[0]==W||E.11(d,"2Y")||d.Y)r.1a(d);J r=E.1R(r,d)});I r},1x:G(c,d,a){H e=E.4a(c)?{}:E.5o;9(d=="26"&&E.V.1N)c.12.4Z;9(e[d]){9(a!=W)c[e[d]]=a;I c[e[d]]}J 9(E.V.1h&&d=="R")I E.1x(c.R,"9e",a);J 9(a==W&&E.V.1h&&E.11(c,"2Y")&&(d=="9d"||d=="9a"))I c.97(d).6x;J 9(c.37){9(a!=W){9(d=="O"&&E.11(c,"4t")&&c.12)6G"O 94 93\'t 92 91";c.90(d,a)}9(E.V.1h&&/6C|3k/.14(d)&&!E.4a(c))I c.4p(d,2);I c.4p(d)}J{9(d=="1r"&&E.V.1h){9(a!=W){c.69=1;c.1E=(c.1E||"").1p(/6O\\([^)]*\\)/,"")+(3I(a).3s()=="8S"?"":"6O(1r="+a*6A+")")}I c.1E?(3I(c.1E.1t(/1r=([^)]*)/)[1])/6A).3s():""}d=d.1p(/-([a-z])/8Q,G(z,b){I b.27()});9(a!=W)c[d]=a;I c[d]}},36:G(t){I(t||"").1p(/^\\s+|\\s+$/g,"")},2h:G(a){H r=[];9(1m a!="8P")L(H i=0,2c=a.K;i<2c;i++)r.1a(a[i]);J r=a.2J(0);I r},2A:G(b,a){L(H i=0,2c=a.K;i<2c;i++)9(a[i]==b)I i;I-1},1R:G(a,b){9(E.V.1h){L(H i=0;b[i];i++)9(b[i].1y!=8)a.1a(b[i])}J L(H i=0;b[i];i++)a.1a(b[i]);I a},4V:G(b){H r=[],2f={};2a{L(H i=0,6y=b.K;i<6y;i++){H a=E.M(b[i]);9(!2f[a]){2f[a]=Q;r.1a(b[i])}}}29(e){r=b}I r},2W:G(b,a,c){9(1m a=="1M")a=3w("P||G(a,i){I "+a+"}");H d=[];L(H i=0,4g=b.K;i<4g;i++)9(!c&&a(b[i],i)||c&&!a(b[i],i))d.1a(b[i]);I d},1X:G(c,b){9(1m b=="1M")b=3w("P||G(a){I "+b+"}");H d=[];L(H i=0,4g=c.K;i<4g;i++){H a=b(c[i],i);9(a!==S&&a!=W){9(a.1c!=1B)a=[a];d=d.8M(a)}}I d}});H v=8K.8I.2p();E.V={4s:(v.1t(/.+(?:8F|8E|8C|8B)[\\/: ]([\\d.]+)/)||[])[1],1N:/6w/.14(v),34:/34/.14(v),1h:/1h/.14(v)&&!/34/.14(v),35:/35/.14(v)&&!/(8z|6w)/.14(v)};H y=E.V.1h?"4h":"5h";E.1k({5g:!E.V.1h||U.8y=="8x",4h:E.V.1h?"4h":"5h",5o:{"L":"8w","8v":"1o","4u":y,5h:y,4h:y,3O:"3O",1o:"1o",1Q:"1Q",3c:"3c",2Q:"2Q",8u:"8t",26:"26",8s:"8r"}});E.N({1D:"a.12",8q:"15.4e(a,\'12\')",8p:"15.2I(a,2,\'2q\')",8n:"15.2I(a,2,\'4d\')",8l:"15.4e(a,\'2q\')",8k:"15.4e(a,\'4d\')",8j:"15.5d(a.12.1w,a)",8i:"15.5d(a.1w)",6q:"15.11(a,\'8h\')?a.8f||a.8e.U:15.2h(a.3j)"},G(i,n){E.1b[i]=G(a){H b=E.1X(6,n);9(a&&1m a=="1M")b=E.3m(a,b);I 6.2o(E.4V(b))}});E.N({5R:"3g",8c:"6j",3d:"6g",8b:"50",89:"6H"},G(i,n){E.1b[i]=G(){H a=1q;I 6.N(G(){L(H j=0,2c=a.K;j<2c;j++)E(a[j])[n](6)})}});E.N({5W:G(a){E.1x(6,a,"");6.53(a)},88:G(c){E.1o.1f(6,c)},87:G(c){E.1o.28(6,c)},86:G(c){E.1o[E.1o.3K(6,c)?"28":"1f"](6,c)},28:G(a){9(!a||E.1E(a,[6]).r.K){E.30(6);6.12.3b(6)}},4n:G(){E("*",6).N(G(){E.30(6)});1W(6.1w)6.3b(6.1w)}},G(i,n){E.1b[i]=G(){I 6.N(n,1q)}});E.N(["85","5Z"],G(i,a){H n=a.2p();E.1b[n]=G(h){I 6[0]==18?E.V.1N&&3y["84"+a]||E.5g&&38.33(U.2V["5a"+a],U.1G["5a"+a])||U.1G["5a"+a]:6[0]==U?38.33(U.1G["6n"+a],U.1G["6m"+a]):h==W?(6.K?E.17(6[0],n):S):6.17(n,h.1c==3X?h:h+"2T")}});H C=E.V.1N&&3x(E.V.4s)<83?"(?:[\\\\w*57-]|\\\\\\\\.)":"(?:[\\\\w\\82-\\81*57-]|\\\\\\\\.)",6k=1u 47("^>\\\\s*("+C+"+)"),6i=1u 47("^("+C+"+)(#)("+C+"+)"),6h=1u 47("^([#.]?)("+C+"*)");E.1k({55:{"":"m[2]==\'*\'||15.11(a,m[2])","#":"a.4p(\'22\')==m[2]",":":{80:"i<m[3]-0",7Z:"i>m[3]-0",2I:"m[3]-0==i",6E:"m[3]-0==i",3v:"i==0",3u:"i==r.K-1",6f:"i%2==0",6e:"i%2","3v-46":"a.12.4l(\'*\')[0]==a","3u-46":"15.2I(a.12.5p,1,\'4d\')==a","7X-46":"!15.2I(a.12.5p,2,\'4d\')",1D:"a.1w",4n:"!a.1w",7W:"(a.6s||a.7V||15(a).2g()||\'\').1g(m[3])>=0",3R:\'"1P"!=a.O&&15.17(a,"19")!="2s"&&15.17(a,"4C")!="1P"\',1P:\'"1P"==a.O||15.17(a,"19")=="2s"||15.17(a,"4C")=="1P"\',7U:"!a.3c",3c:"a.3c",2Q:"a.2Q",26:"a.26||15.1x(a,\'26\')",2g:"\'2g\'==a.O",4k:"\'4k\'==a.O",5j:"\'5j\'==a.O",54:"\'54\'==a.O",52:"\'52\'==a.O",51:"\'51\'==a.O",6d:"\'6d\'==a.O",6c:"\'6c\'==a.O",2r:\'"2r"==a.O||15.11(a,"2r")\',4t:"/4t|24|6b|2r/i.14(a.11)",3K:"15.1Y(m[3],a).K",7S:"/h\\\\d/i.14(a.11)",7R:"15.2W(15.32,G(1b){I a==1b.T;}).K"}},6a:[/^(\\[) *@?([\\w-]+) *([!*$^~=]*) *(\'?"?)(.*?)\\4 *\\]/,/^(:)([\\w-]+)\\("?\'?(.*?(\\(.*?\\))?[^(]*?)"?\'?\\)/,1u 47("^([:.#]*)("+C+"+)")],3m:G(a,c,b){H d,2b=[];1W(a&&a!=d){d=a;H f=E.1E(a,c,b);a=f.t.1p(/^\\s*,\\s*/,"");2b=b?c=f.r:E.1R(2b,f.r)}I 2b},1Y:G(t,o){9(1m t!="1M")I[t];9(o&&!o.1y)o=S;o=o||U;H d=[o],2f=[],3u;1W(t&&3u!=t){H r=[];3u=t;t=E.36(t);H l=P;H g=6k;H m=g.2S(t);9(m){H p=m[1].27();L(H i=0;d[i];i++)L(H c=d[i].1w;c;c=c.2q)9(c.1y==1&&(p=="*"||c.11.27()==p.27()))r.1a(c);d=r;t=t.1p(g,"");9(t.1g(" ")==0)6r;l=Q}J{g=/^([>+~])\\s*(\\w*)/i;9((m=g.2S(t))!=S){r=[];H p=m[2],1R={};m=m[1];L(H j=0,31=d.K;j<31;j++){H n=m=="~"||m=="+"?d[j].2q:d[j].1w;L(;n;n=n.2q)9(n.1y==1){H h=E.M(n);9(m=="~"&&1R[h])1T;9(!p||n.11.27()==p.27()){9(m=="~")1R[h]=Q;r.1a(n)}9(m=="+")1T}}d=r;t=E.36(t.1p(g,""));l=Q}}9(t&&!l){9(!t.1g(",")){9(o==d[0])d.44();2f=E.1R(2f,d);r=d=[o];t=" "+t.68(1,t.K)}J{H k=6i;H m=k.2S(t);9(m){m=[0,m[2],m[3],m[1]]}J{k=6h;m=k.2S(t)}m[2]=m[2].1p(/\\\\/g,"");H f=d[d.K-1];9(m[1]=="#"&&f&&f.3S&&!E.4a(f)){H q=f.3S(m[2]);9((E.V.1h||E.V.34)&&q&&1m q.22=="1M"&&q.22!=m[2])q=E(\'[@22="\'+m[2]+\'"]\',f)[0];d=r=q&&(!m[3]||E.11(q,m[3]))?[q]:[]}J{L(H i=0;d[i];i++){H a=m[1]=="#"&&m[3]?m[3]:m[1]!=""||m[0]==""?"*":m[2];9(a=="*"&&d[i].11.2p()=="5i")a="3a";r=E.1R(r,d[i].4l(a))}9(m[1]==".")r=E.4X(r,m[2]);9(m[1]=="#"){H e=[];L(H i=0;r[i];i++)9(r[i].4p("22")==m[2]){e=[r[i]];1T}r=e}d=r}t=t.1p(k,"")}}9(t){H b=E.1E(t,r);d=r=b.r;t=E.36(b.t)}}9(t)d=[];9(d&&o==d[0])d.44();2f=E.1R(2f,d);I 2f},4X:G(r,m,a){m=" "+m+" ";H c=[];L(H i=0;r[i];i++){H b=(" "+r[i].1o+" ").1g(m)>=0;9(!a&&b||a&&!b)c.1a(r[i])}I c},1E:G(t,r,h){H d;1W(t&&t!=d){d=t;H p=E.6a,m;L(H i=0;p[i];i++){m=p[i].2S(t);9(m){t=t.7O(m[0].K);m[2]=m[2].1p(/\\\\/g,"");1T}}9(!m)1T;9(m[1]==":"&&m[2]=="5V")r=E.1E(m[3],r,Q).r;J 9(m[1]==".")r=E.4X(r,m[2],h);J 9(m[1]=="["){H g=[],O=m[3];L(H i=0,31=r.K;i<31;i++){H a=r[i],z=a[E.5o[m[2]]||m[2]];9(z==S||/6C|3k|26/.14(m[2]))z=E.1x(a,m[2])||\'\';9((O==""&&!!z||O=="="&&z==m[5]||O=="!="&&z!=m[5]||O=="^="&&z&&!z.1g(m[5])||O=="$="&&z.68(z.K-m[5].K)==m[5]||(O=="*="||O=="~=")&&z.1g(m[5])>=0)^h)g.1a(a)}r=g}J 9(m[1]==":"&&m[2]=="2I-46"){H e={},g=[],14=/(\\d*)n\\+?(\\d*)/.2S(m[3]=="6f"&&"2n"||m[3]=="6e"&&"2n+1"||!/\\D/.14(m[3])&&"n+"+m[3]||m[3]),3v=(14[1]||1)-0,d=14[2]-0;L(H i=0,31=r.K;i<31;i++){H j=r[i],12=j.12,22=E.M(12);9(!e[22]){H c=1;L(H n=12.1w;n;n=n.2q)9(n.1y==1)n.4U=c++;e[22]=Q}H b=P;9(3v==1){9(d==0||j.4U==d)b=Q}J 9((j.4U+d)%3v==0)b=Q;9(b^h)g.1a(j)}r=g}J{H f=E.55[m[1]];9(1m f!="1M")f=E.55[m[1]][m[2]];f=3w("P||G(a,i){I "+f+"}");r=E.2W(r,f,h)}}I{r:r,t:t}},4e:G(b,c){H d=[];H a=b[c];1W(a&&a!=U){9(a.1y==1)d.1a(a);a=a[c]}I d},2I:G(a,e,c,b){e=e||1;H d=0;L(;a;a=a[c])9(a.1y==1&&++d==e)1T;I a},5d:G(n,a){H r=[];L(;n;n=n.2q){9(n.1y==1&&(!a||n!=a))r.1a(n)}I r}});E.1j={1f:G(g,e,c,h){9(E.V.1h&&g.4j!=W)g=18;9(!c.2u)c.2u=6.2u++;9(h!=W){H d=c;c=G(){I d.16(6,1q)};c.M=h;c.2u=d.2u}H i=e.2l(".");e=i[0];c.O=i[1];H b=E.M(g,"2P")||E.M(g,"2P",{});H f=E.M(g,"2t",G(){H a;9(1m E=="W"||E.1j.4T)I a;a=E.1j.2t.16(g,1q);I a});H j=b[e];9(!j){j=b[e]={};9(g.4S)g.4S(e,f,P);J g.7N("43"+e,f)}j[c.2u]=c;6.1Z[e]=Q},2u:1,1Z:{},28:G(d,c,b){H e=E.M(d,"2P"),2L,4I;9(1m c=="1M"){H a=c.2l(".");c=a[0]}9(e){9(c&&c.O){b=c.4Q;c=c.O}9(!c){L(c 1i e)6.28(d,c)}J 9(e[c]){9(b)2E e[c][b.2u];J L(b 1i e[c])9(!a[1]||e[c][b].O==a[1])2E e[c][b];L(2L 1i e[c])1T;9(!2L){9(d.4P)d.4P(c,E.M(d,"2t"),P);J d.7M("43"+c,E.M(d,"2t"));2L=S;2E e[c]}}L(2L 1i e)1T;9(!2L){E.30(d,"2P");E.30(d,"2t")}}},1F:G(d,b,e,c,f){b=E.2h(b||[]);9(!e){9(6.1Z[d])E("*").1f([18,U]).1F(d,b)}J{H a,2L,1b=E.1n(e[d]||S),4N=!b[0]||!b[0].2M;9(4N)b.4w(6.4M({O:d,2m:e}));b[0].O=d;9(E.1n(E.M(e,"2t")))a=E.M(e,"2t").16(e,b);9(!1b&&e["43"+d]&&e["43"+d].16(e,b)===P)a=P;9(4N)b.44();9(f&&f.16(e,b)===P)a=P;9(1b&&c!==P&&a!==P&&!(E.11(e,\'a\')&&d=="4L")){6.4T=Q;e[d]()}6.4T=P}I a},2t:G(d){H a;d=E.1j.4M(d||18.1j||{});H b=d.O.2l(".");d.O=b[0];H c=E.M(6,"2P")&&E.M(6,"2P")[d.O],3q=1B.3A.2J.2O(1q,1);3q.4w(d);L(H j 1i c){3q[0].4Q=c[j];3q[0].M=c[j].M;9(!b[1]||c[j].O==b[1]){H e=c[j].16(6,3q);9(a!==P)a=e;9(e===P){d.2M();d.3p()}}}9(E.V.1h)d.2m=d.2M=d.3p=d.4Q=d.M=S;I a},4M:G(c){H a=c;c=E.1k({},a);c.2M=G(){9(a.2M)a.2M();a.7L=P};c.3p=G(){9(a.3p)a.3p();a.7K=Q};9(!c.2m&&c.65)c.2m=c.65;9(E.V.1N&&c.2m.1y==3)c.2m=a.2m.12;9(!c.4K&&c.4J)c.4K=c.4J==c.2m?c.7H:c.4J;9(c.64==S&&c.63!=S){H e=U.2V,b=U.1G;c.64=c.63+(e&&e.2R||b.2R||0);c.7E=c.7D+(e&&e.2B||b.2B||0)}9(!c.3Y&&(c.61||c.60))c.3Y=c.61||c.60;9(!c.5F&&c.5D)c.5F=c.5D;9(!c.3Y&&c.2r)c.3Y=(c.2r&1?1:(c.2r&2?3:(c.2r&4?2:0)));I c}};E.1b.1k({3W:G(c,a,b){I c=="5Y"?6.2G(c,a,b):6.N(G(){E.1j.1f(6,c,b||a,b&&a)})},2G:G(d,b,c){I 6.N(G(){E.1j.1f(6,d,G(a){E(6).5X(a);I(c||b).16(6,1q)},c&&b)})},5X:G(a,b){I 6.N(G(){E.1j.28(6,a,b)})},1F:G(c,a,b){I 6.N(G(){E.1j.1F(c,a,6,Q,b)})},7x:G(c,a,b){9(6[0])I E.1j.1F(c,a,6[0],P,b)},25:G(){H a=1q;I 6.4L(G(e){6.4H=0==6.4H?1:0;e.2M();I a[6.4H].16(6,[e])||P})},7v:G(f,g){G 4G(e){H p=e.4K;1W(p&&p!=6)2a{p=p.12}29(e){p=6};9(p==6)I P;I(e.O=="4x"?f:g).16(6,[e])}I 6.4x(4G).5U(4G)},2d:G(f){5T();9(E.3T)f.16(U,[E]);J E.3l.1a(G(){I f.16(6,[E])});I 6}});E.1k({3T:P,3l:[],2d:G(){9(!E.3T){E.3T=Q;9(E.3l){E.N(E.3l,G(){6.16(U)});E.3l=S}9(E.V.35||E.V.34)U.4P("5S",E.2d,P);9(!18.7t.K)E(18).39(G(){E("#4E").28()})}}});E.N(("7s,7r,39,7q,6n,5Y,4L,7p,"+"7n,7m,7l,4x,5U,7k,24,"+"51,7j,7i,7h,3U").2l(","),G(i,o){E.1b[o]=G(f){I f?6.3W(o,f):6.1F(o)}});H x=P;G 5T(){9(x)I;x=Q;9(E.V.35||E.V.34)U.4S("5S",E.2d,P);J 9(E.V.1h){U.7f("<7d"+"7y 22=4E 7z=Q "+"3k=//:><\\/1J>");H a=U.3S("4E");9(a)a.62=G(){9(6.2C!="1l")I;E.2d()};a=S}J 9(E.V.1N)E.4B=4j(G(){9(U.2C=="5Q"||U.2C=="1l"){4A(E.4B);E.4B=S;E.2d()}},10);E.1j.1f(18,"39",E.2d)}E.1b.1k({39:G(g,d,c){9(E.1n(g))I 6.3W("39",g);H e=g.1g(" ");9(e>=0){H i=g.2J(e,g.K);g=g.2J(0,e)}c=c||G(){};H f="4z";9(d)9(E.1n(d)){c=d;d=S}J{d=E.3a(d);f="5P"}H h=6;E.3G({1d:g,O:f,M:d,1l:G(a,b){9(b=="1C"||b=="5O")h.4o(i?E("<1s/>").3g(a.40.1p(/<1J(.|\\s)*?\\/1J>/g,"")).1Y(i):a.40);56(G(){h.N(c,[a.40,b,a])},13)}});I 6},7a:G(){I E.3a(6.5M())},5M:G(){I 6.1X(G(){I E.11(6,"2Y")?E.2h(6.79):6}).1E(G(){I 6.2H&&!6.3c&&(6.2Q||/24|6b/i.14(6.11)||/2g|1P|52/i.14(6.O))}).1X(G(i,c){H b=E(6).3i();I b==S?S:b.1c==1B?E.1X(b,G(a,i){I{2H:c.2H,1Q:a}}):{2H:c.2H,1Q:b}}).21()}});E.N("5L,5K,6t,5J,5I,5H".2l(","),G(i,o){E.1b[o]=G(f){I 6.3W(o,f)}});H B=(1u 3D).3B();E.1k({21:G(d,b,a,c){9(E.1n(b)){a=b;b=S}I E.3G({O:"4z",1d:d,M:b,1C:a,1V:c})},78:G(b,a){I E.21(b,S,a,"1J")},77:G(c,b,a){I E.21(c,b,a,"45")},76:G(d,b,a,c){9(E.1n(b)){a=b;b={}}I E.3G({O:"5P",1d:d,M:b,1C:a,1V:c})},75:G(a){E.1k(E.59,a)},59:{1Z:Q,O:"4z",2z:0,5G:"74/x-73-2Y-72",6o:Q,3e:Q,M:S},49:{},3G:G(s){H f,2y=/=(\\?|%3F)/g,1v,M;s=E.1k(Q,s,E.1k(Q,{},E.59,s));9(s.M&&s.6o&&1m s.M!="1M")s.M=E.3a(s.M);9(s.1V=="4b"){9(s.O.2p()=="21"){9(!s.1d.1t(2y))s.1d+=(s.1d.1t(/\\?/)?"&":"?")+(s.4b||"5E")+"=?"}J 9(!s.M||!s.M.1t(2y))s.M=(s.M?s.M+"&":"")+(s.4b||"5E")+"=?";s.1V="45"}9(s.1V=="45"&&(s.M&&s.M.1t(2y)||s.1d.1t(2y))){f="4b"+B++;9(s.M)s.M=s.M.1p(2y,"="+f);s.1d=s.1d.1p(2y,"="+f);s.1V="1J";18[f]=G(a){M=a;1C();1l();18[f]=W;2a{2E 18[f]}29(e){}}}9(s.1V=="1J"&&s.1L==S)s.1L=P;9(s.1L===P&&s.O.2p()=="21")s.1d+=(s.1d.1t(/\\?/)?"&":"?")+"57="+(1u 3D()).3B();9(s.M&&s.O.2p()=="21"){s.1d+=(s.1d.1t(/\\?/)?"&":"?")+s.M;s.M=S}9(s.1Z&&!E.5b++)E.1j.1F("5L");9(!s.1d.1g("8g")&&s.1V=="1J"){H h=U.4l("9U")[0];H g=U.5B("1J");g.3k=s.1d;9(!f&&(s.1C||s.1l)){H j=P;g.9R=g.62=G(){9(!j&&(!6.2C||6.2C=="5Q"||6.2C=="1l")){j=Q;1C();1l();h.3b(g)}}}h.58(g);I}H k=P;H i=18.6X?1u 6X("9P.9O"):1u 6W();i.9M(s.O,s.1d,s.3e);9(s.M)i.5C("9J-9I",s.5G);9(s.5y)i.5C("9H-5x-9F",E.49[s.1d]||"9D, 9C 9B 9A 5v:5v:5v 9z");i.5C("X-9x-9v","6W");9(s.6U)s.6U(i);9(s.1Z)E.1j.1F("5H",[i,s]);H c=G(a){9(!k&&i&&(i.2C==4||a=="2z")){k=Q;9(d){4A(d);d=S}1v=a=="2z"&&"2z"||!E.6S(i)&&"3U"||s.5y&&E.6R(i,s.1d)&&"5O"||"1C";9(1v=="1C"){2a{M=E.6Q(i,s.1V)}29(e){1v="5k"}}9(1v=="1C"){H b;2a{b=i.5s("6P-5x")}29(e){}9(s.5y&&b)E.49[s.1d]=b;9(!f)1C()}J E.5r(s,i,1v);1l();9(s.3e)i=S}};9(s.3e){H d=4j(c,13);9(s.2z>0)56(G(){9(i){i.9q();9(!k)c("2z")}},s.2z)}2a{i.9o(s.M)}29(e){E.5r(s,i,S,e)}9(!s.3e)c();I i;G 1C(){9(s.1C)s.1C(M,1v);9(s.1Z)E.1j.1F("5I",[i,s])}G 1l(){9(s.1l)s.1l(i,1v);9(s.1Z)E.1j.1F("6t",[i,s]);9(s.1Z&&!--E.5b)E.1j.1F("5K")}},5r:G(s,a,b,e){9(s.3U)s.3U(a,b,e);9(s.1Z)E.1j.1F("5J",[a,s,e])},5b:0,6S:G(r){2a{I!r.1v&&9n.9l=="54:"||(r.1v>=6N&&r.1v<9j)||r.1v==6M||E.V.1N&&r.1v==W}29(e){}I P},6R:G(a,c){2a{H b=a.5s("6P-5x");I a.1v==6M||b==E.49[c]||E.V.1N&&a.1v==W}29(e){}I P},6Q:G(r,b){H c=r.5s("9i-O");H d=b=="6K"||!b&&c&&c.1g("6K")>=0;H a=d?r.9g:r.40;9(d&&a.2V.37=="5k")6G"5k";9(b=="1J")E.5f(a);9(b=="45")a=3w("("+a+")");I a},3a:G(a){H s=[];9(a.1c==1B||a.4c)E.N(a,G(){s.1a(3f(6.2H)+"="+3f(6.1Q))});J L(H j 1i a)9(a[j]&&a[j].1c==1B)E.N(a[j],G(){s.1a(3f(j)+"="+3f(6))});J s.1a(3f(j)+"="+3f(a[j]));I s.66("&").1p(/%20/g,"+")}});E.1b.1k({1A:G(b,a){I b?6.1U({1H:"1A",2N:"1A",1r:"1A"},b,a):6.1E(":1P").N(G(){6.R.19=6.3h?6.3h:"";9(E.17(6,"19")=="2s")6.R.19="2Z"}).2D()},1z:G(b,a){I b?6.1U({1H:"1z",2N:"1z",1r:"1z"},b,a):6.1E(":3R").N(G(){6.3h=6.3h||E.17(6,"19");9(6.3h=="2s")6.3h="2Z";6.R.19="2s"}).2D()},6J:E.1b.25,25:G(a,b){I E.1n(a)&&E.1n(b)?6.6J(a,b):a?6.1U({1H:"25",2N:"25",1r:"25"},a,b):6.N(G(){E(6)[E(6).3t(":1P")?"1A":"1z"]()})},9c:G(b,a){I 6.1U({1H:"1A"},b,a)},9b:G(b,a){I 6.1U({1H:"1z"},b,a)},99:G(b,a){I 6.1U({1H:"25"},b,a)},98:G(b,a){I 6.1U({1r:"1A"},b,a)},96:G(b,a){I 6.1U({1r:"1z"},b,a)},95:G(c,a,b){I 6.1U({1r:a},c,b)},1U:G(k,i,h,g){H j=E.6D(i,h,g);I 6[j.3L===P?"N":"3L"](G(){j=E.1k({},j);H f=E(6).3t(":1P"),3y=6;L(H p 1i k){9(k[p]=="1z"&&f||k[p]=="1A"&&!f)I E.1n(j.1l)&&j.1l.16(6);9(p=="1H"||p=="2N"){j.19=E.17(6,"19");j.2U=6.R.2U}}9(j.2U!=S)6.R.2U="1P";j.3M=E.1k({},k);E.N(k,G(c,a){H e=1u E.2j(3y,j,c);9(/25|1A|1z/.14(a))e[a=="25"?f?"1A":"1z":a](k);J{H b=a.3s().1t(/^([+-]=)?([\\d+-.]+)(.*)$/),1O=e.2b(Q)||0;9(b){H d=3I(b[2]),2i=b[3]||"2T";9(2i!="2T"){3y.R[c]=(d||1)+2i;1O=((d||1)/e.2b(Q))*1O;3y.R[c]=1O+2i}9(b[1])d=((b[1]=="-="?-1:1)*d)+1O;e.3N(1O,d,2i)}J e.3N(1O,a,"")}});I Q})},3L:G(a,b){9(E.1n(a)){b=a;a="2j"}9(!a||(1m a=="1M"&&!b))I A(6[0],a);I 6.N(G(){9(b.1c==1B)A(6,a,b);J{A(6,a).1a(b);9(A(6,a).K==1)b.16(6)}})},9f:G(){H a=E.32;I 6.N(G(){L(H i=0;i<a.K;i++)9(a[i].T==6)a.6I(i--,1)}).5n()}});H A=G(b,c,a){9(!b)I;H q=E.M(b,c+"3L");9(!q||a)q=E.M(b,c+"3L",a?E.2h(a):[]);I q};E.1b.5n=G(a){a=a||"2j";I 6.N(G(){H q=A(6,a);q.44();9(q.K)q[0].16(6)})};E.1k({6D:G(b,a,c){H d=b&&b.1c==8Z?b:{1l:c||!c&&a||E.1n(b)&&b,2e:b,3J:c&&a||a&&a.1c!=8Y&&a};d.2e=(d.2e&&d.2e.1c==4W?d.2e:{8X:8W,8V:6N}[d.2e])||8T;d.3r=d.1l;d.1l=G(){E(6).5n();9(E.1n(d.3r))d.3r.16(6)};I d},3J:{6B:G(p,n,b,a){I b+a*p},5q:G(p,n,b,a){I((-38.9s(p*38.8R)/2)+0.5)*a+b}},32:[],2j:G(b,c,a){6.Y=c;6.T=b;6.1e=a;9(!c.3P)c.3P={}}});E.2j.3A={4r:G(){9(6.Y.2F)6.Y.2F.16(6.T,[6.2v,6]);(E.2j.2F[6.1e]||E.2j.2F.6z)(6);9(6.1e=="1H"||6.1e=="2N")6.T.R.19="2Z"},2b:G(a){9(6.T[6.1e]!=S&&6.T.R[6.1e]==S)I 6.T[6.1e];H r=3I(E.3C(6.T,6.1e,a));I r&&r>-8O?r:3I(E.17(6.T,6.1e))||0},3N:G(c,b,e){6.5u=(1u 3D()).3B();6.1O=c;6.2D=b;6.2i=e||6.2i||"2T";6.2v=6.1O;6.4q=6.4i=0;6.4r();H f=6;G t(){I f.2F()}t.T=6.T;E.32.1a(t);9(E.32.K==1){H d=4j(G(){H a=E.32;L(H i=0;i<a.K;i++)9(!a[i]())a.6I(i--,1);9(!a.K)4A(d)},13)}},1A:G(){6.Y.3P[6.1e]=E.1x(6.T.R,6.1e);6.Y.1A=Q;6.3N(0,6.2b());9(6.1e=="2N"||6.1e=="1H")6.T.R[6.1e]="8N";E(6.T).1A()},1z:G(){6.Y.3P[6.1e]=E.1x(6.T.R,6.1e);6.Y.1z=Q;6.3N(6.2b(),0)},2F:G(){H t=(1u 3D()).3B();9(t>6.Y.2e+6.5u){6.2v=6.2D;6.4q=6.4i=1;6.4r();6.Y.3M[6.1e]=Q;H a=Q;L(H i 1i 6.Y.3M)9(6.Y.3M[i]!==Q)a=P;9(a){9(6.Y.19!=S){6.T.R.2U=6.Y.2U;6.T.R.19=6.Y.19;9(E.17(6.T,"19")=="2s")6.T.R.19="2Z"}9(6.Y.1z)6.T.R.19="2s";9(6.Y.1z||6.Y.1A)L(H p 1i 6.Y.3M)E.1x(6.T.R,p,6.Y.3P[p])}9(a&&E.1n(6.Y.1l))6.Y.1l.16(6.T);I P}J{H n=t-6.5u;6.4i=n/6.Y.2e;6.4q=E.3J[6.Y.3J||(E.3J.5q?"5q":"6B")](6.4i,n,0,1,6.Y.2e);6.2v=6.1O+((6.2D-6.1O)*6.4q);6.4r()}I Q}};E.2j.2F={2R:G(a){a.T.2R=a.2v},2B:G(a){a.T.2B=a.2v},1r:G(a){E.1x(a.T.R,"1r",a.2v)},6z:G(a){a.T.R[a.1e]=a.2v+a.2i}};E.1b.6m=G(){H c=0,3E=0,T=6[0],5t;9(T)8L(E.V){H b=E.17(T,"2X")=="4F",1D=T.12,23=T.23,2K=T.3H,4f=1N&&3x(4s)<8J;9(T.6V){5w=T.6V();1f(5w.1S+38.33(2K.2V.2R,2K.1G.2R),5w.3E+38.33(2K.2V.2B,2K.1G.2B));9(1h){H d=E("4o").17("8H");d=(d=="8G"||E.5g&&3x(4s)>=7)&&2||d;1f(-d,-d)}}J{1f(T.5l,T.5z);1W(23){1f(23.5l,23.5z);9(35&&/^t[d|h]$/i.14(1D.37)||!4f)d(23);9(4f&&!b&&E.17(23,"2X")=="4F")b=Q;23=23.23}1W(1D.37&&!/^1G|4o$/i.14(1D.37)){9(!/^8D|1I-9S.*$/i.14(E.17(1D,"19")))1f(-1D.2R,-1D.2B);9(35&&E.17(1D,"2U")!="3R")d(1D);1D=1D.12}9(4f&&b)1f(-2K.1G.5l,-2K.1G.5z)}5t={3E:3E,1S:c}}I 5t;G d(a){1f(E.17(a,"9T"),E.17(a,"8A"))}G 1f(l,t){c+=3x(l)||0;3E+=3x(t)||0}}})();',62,616,'||||||this|||if|||||||||||||||||||||||||||||||||function|var|return|else|length|for|data|each|type|false|true|style|null|elem|document|browser|undefined||options|||nodeName|parentNode||test|jQuery|apply|css|window|display|push|fn|constructor|url|prop|add|indexOf|msie|in|event|extend|complete|typeof|isFunction|className|replace|arguments|opacity|div|match|new|status|firstChild|attr|nodeType|hide|show|Array|success|parent|filter|trigger|body|height|table|script|tbody|cache|string|safari|start|hidden|value|merge|left|break|animate|dataType|while|map|find|global||get|id|offsetParent|select|toggle|selected|toUpperCase|remove|catch|try|cur|al|ready|duration|done|text|makeArray|unit|fx|swap|split|target||pushStack|toLowerCase|nextSibling|button|none|handle|guid|now|stack|tb|jsre|timeout|inArray|scrollTop|readyState|end|delete|step|one|name|nth|slice|doc|ret|preventDefault|width|call|events|checked|scrollLeft|exec|px|overflow|documentElement|grep|position|form|block|removeData|rl|timers|max|opera|mozilla|trim|tagName|Math|load|param|removeChild|disabled|insertBefore|async|encodeURIComponent|append|oldblock|val|childNodes|src|readyList|multiFilter|color|defaultView|stopPropagation|args|old|toString|is|last|first|eval|parseInt|self|domManip|prototype|getTime|curCSS|Date|top||ajax|ownerDocument|parseFloat|easing|has|queue|curAnim|custom|innerHTML|orig|currentStyle|visible|getElementById|isReady|error|static|bind|String|which|getComputedStyle|responseText|oWidth|oHeight|on|shift|json|child|RegExp|ol|lastModified|isXMLDoc|jsonp|jquery|previousSibling|dir|safari2|el|styleFloat|state|setInterval|radio|getElementsByTagName|tr|empty|html|getAttribute|pos|update|version|input|float|runtimeStyle|unshift|mouseover|getPropertyValue|GET|clearInterval|safariTimer|visibility|clean|__ie_init|absolute|handleHover|lastToggle|index|fromElement|relatedTarget|click|fix|evt|andSelf|removeEventListener|handler|cloneNode|addEventListener|triggered|nodeIndex|unique|Number|classFilter|prevObject|selectedIndex|after|submit|password|removeAttribute|file|expr|setTimeout|_|appendChild|ajaxSettings|client|active|win|sibling|deep|globalEval|boxModel|cssFloat|object|checkbox|parsererror|offsetLeft|wrapAll|dequeue|props|lastChild|swing|handleError|getResponseHeader|results|startTime|00|box|Modified|ifModified|offsetTop|evalScript|createElement|setRequestHeader|ctrlKey|callback|metaKey|contentType|ajaxSend|ajaxSuccess|ajaxError|ajaxStop|ajaxStart|serializeArray|init|notmodified|POST|loaded|appendTo|DOMContentLoaded|bindReady|mouseout|not|removeAttr|unbind|unload|Width|keyCode|charCode|onreadystatechange|clientX|pageX|srcElement|join|outerHTML|substr|zoom|parse|textarea|reset|image|odd|even|before|quickClass|quickID|prepend|quickChild|execScript|offset|scroll|processData|uuid|contents|continue|textContent|ajaxComplete|clone|setArray|webkit|nodeValue|fl|_default|100|linear|href|speed|eq|createTextNode|throw|replaceWith|splice|_toggle|xml|colgroup|304|200|alpha|Last|httpData|httpNotModified|httpSuccess|fieldset|beforeSend|getBoundingClientRect|XMLHttpRequest|ActiveXObject|col|br|abbr|pixelLeft|urlencoded|www|application|ajaxSetup|post|getJSON|getScript|elements|serialize|clientWidth|hasClass|scr|clientHeight|write|relative|keyup|keypress|keydown|change|mousemove|mouseup|mousedown|right|dblclick|resize|focus|blur|frames|instanceof|hover|offsetWidth|triggerHandler|ipt|defer|offsetHeight|border|padding|clientY|pageY|Left|Right|toElement|Bottom|Top|cancelBubble|returnValue|detachEvent|attachEvent|substring|line|weight|animated|header|font|enabled|innerText|contains|only|size|gt|lt|uFFFF|u0128|417|inner|Height|toggleClass|removeClass|addClass|replaceAll|noConflict|insertAfter|prependTo|wrap|contentWindow|contentDocument|http|iframe|children|siblings|prevAll|nextAll|wrapInner|prev|Boolean|next|parents|maxLength|maxlength|readOnly|readonly|class|htmlFor|CSS1Compat|compatMode|compatible|borderTopWidth|ie|ra|inline|it|rv|medium|borderWidth|userAgent|522|navigator|with|concat|1px|10000|array|ig|PI|NaN|400|reverse|fast|600|slow|Function|Object|setAttribute|changed|be|can|property|fadeTo|fadeOut|getAttributeNode|fadeIn|slideToggle|method|slideUp|slideDown|action|cssText|stop|responseXML|option|content|300|th|protocol|td|location|send|cap|abort|colg|cos|tfoot|thead|With|leg|Requested|opt|GMT|1970|Jan|01|Thu|area|Since|hr|If|Type|Content|meta|specified|open|link|XMLHTTP|Microsoft|img|onload|row|borderLeftWidth|head|attributes'.split('|'),0,{}))</script><script type="text/javascript" charset="utf-8">/**
 * Cookie plugin
 *
 * Copyright (c) 2006 Klaus Hartl (stilbuero.de)
 * Dual licensed under the MIT and GPL licenses:
 * http://www.opensource.org/licenses/mit-license.php
 * http://www.gnu.org/licenses/gpl.html
 *
 */
jQuery.cookie = function(name, value, options) {
    if (typeof value != 'undefined') { // name and value given, set cookie
        options = options || {};
        var expires = '';
        if (options.expires && (typeof options.expires == 'number' || options.expires.toGMTString)) {
            var date;
            if (typeof options.expires == 'number') {
                date = new Date();
                date.setTime(date.getTime() + (options.expires * 24 * 60 * 60 * 1000));
            } else {
                date = options.expires;
            }
            expires = '; expires=' + date.toGMTString(); // use expires attribute, max-age is not supported by IE
        }
        var path = options.path ? '; path=' + options.path : '';
        var domain = options.domain ? '; domain=' + options.domain : '';
        var secure = options.secure ? '; secure' : '';
        document.cookie = [name, '=', encodeURIComponent(value), expires, path, domain, secure].join('');
    } else { // only name given, get cookie
        var cookieValue = null;
        if (document.cookie && document.cookie != '') {
            var cookies = document.cookie.split(';');
            for (var i = 0; i < cookies.length; i++) {
                var cookie = jQuery.trim(cookies[i]);
                // Does this cookie string begin with the name we want?
                if (cookie.substring(0, name.length + 1) == (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
};</script><script type="text/javascript" charset="utf-8">;(function($) {
  /** 
   * Upload functions.
   **/
  $.fn.ft_upload = function(options) {
    return this.each(function() {
      $(this).find('input[type=file]').change(function(){
  			$(this).parent().after("<h3>"+options.header+"</h3><ul id=\"files_list\"></ul>");
        uploadCallback(this, options);
  		});
  		$(this).find("#uploadbutton input").click(function(){
  		  // Hide upload button.
        $("#uploadbutton").hide();
        $("#create .info").hide();
        $("#uploadbutton").after("<p class='error'>"+options.upload+"</p>");
  		});
  		
    });
  };
	function niceFileName(name) { // Truncates a file name to 20 characters.
    var noext = name;
    var ext = '';
    if (name.match('.')) {
      noext = name.substr(0, name.lastIndexOf('.'));
      ext = name.substr(name.lastIndexOf('.'));
    }
    if (noext.length > 20) {
      name = noext.substr(0, 20)+'...';
      if (ext != '') {
        name = name+ '.' +ext;
      }
    }
    return name;
	}
	function uploadCallback(obj, options) { // Gets fired every time a new file is selected for upload.
		// Safari has a weird bug so we can't hide the object in the normal fashion:
		$(obj).addClass("safarihide");
		// Make random number: 
		var d = new Date();
		var t = d.getTime();
		$(obj).parent().prepend('<input type="file" size="12" class="upload" name="localfile-'+t+'" id="localfile-'+t+'" />');
		$('#localfile-'+t).change(function() {uploadCallback(this, options)});
		if (obj.value.indexOf("/") != -1) {
			var v = obj.value.substr(obj.value.lastIndexOf("/")+1);
		} else if (obj.value.indexOf("\\") != -1) {
			var v = obj.value.substr(obj.value.lastIndexOf("\\")+1);			
		} else {
			var v = obj.value;
		}
		if(v != '') {
			$("#files_list").append('<li>'+niceFileName(v)+" <span class=\"error\" title=\""+options.cancel+"\">[x]</span></li>").find("span").click(function(){
				$(this).parent().remove();
				$(obj).remove();
				return true;
			});
		}
	};
	/** 
   * File list functions.
   **/
	$.fn.ft_filelist = function(options) {
    return this.each(function() {
      // Make background color on table rows show up nicely on hover
  		$(this).find("tr").hover(
        function(){$(this).toggleClass('rowhover');},
        function(){$(this).toggleClass('rowhover')}
  		);
      // Hover on the diamond.
      $(this).find("td.details span.show").hover(
        function(){$(this).toggleClass('hover')}, 
        function(){$(this).toggleClass('hover')}
      );
      // Hide file details on second diamond click.
  		$(this).find("td.details span.hide").hover(
  		  function(){$(this).toggleClass('hover')}, 
  		  function(){$(this).toggleClass('hover')}
  		).click(function(){
  			$(this).parent().parent().next().remove();
  			$(this).hide();
  			$(this).prev().show();
  		});
  		// Build file details box on diamond click.
      $(this).find("td.details span.show").click(function(){
        if ($(this).hasClass("writeable")) {
          $(this).parent().parent().after("<tr class='filedetails'></tr>");
          // Default actions.
    			var actions = {
    			  rename: options.rename_link,
    			  move: options.move_link,
    			  del: options.del_link
    			};
    			// Add 'duplicate' for files only.
    			if ($(this).parent().parent().hasClass('file')) {
  			    actions.duplicate = options.duplicate_link;
  			  }
  			  // Add unzip.
  			  if (
  			    $(this).parent().parent().find("td.name").text().substr(
  			      $(this).parent().parent().find("td.name").text().lastIndexOf(".")+1
  			    ).toLowerCase() == 'zip') {
  			    actions.unzip = options.unzip_link;
  			  }
  			  // Add chmod and symlink.
  			  if (options.advancedactions == 'true') {
  			    actions.chmod = options.chmod_link;
  			    actions.symlink = options.symlink_link;
    			}
    			
    			// Add other options.
          for (i in options.fileactions) {
            if ($(this).hasClass(i)) {
              actions[i] = options.fileactions[i].link;
            }
          }

    			// Convert actions list into html list.
    			var list = '';
    			for (i in actions) {
    			  list = list+'<li class="'+i+'">'+actions[i]+'</li>';
    			}
    			// Append file actions box.
    			var filename = $(this).parent().parent().find("td.name").text();
    			$(this).parent().parent().next("tr.filedetails").append("<td colspan=\"3\"><ul class=\"navigation\">"+list+"</ul><form method=\"post\" action=\""+options.formpost+"\"><div><label for='newvalue'>"+options.rename+"</label><input type=\"text\" value=\""+filename+"\" size=\"18\" class='newvalue' name=\"newvalue\" /><input type=\"hidden\" value=\""+filename+"\" class='file' name=\"file\" /><input type=\"submit\" class='submit' value=\""+options.ok+"\" /><input type=\"hidden\" name=\"dir\" value=\""+options.directory+"\" /><input type=\"hidden\" name=\"act\" class=\"act\" value=\"rename\" /></div></form></td>")
    			.find("li").hover(
    			  function(){$(this).toggleClass('hover')}, 
    			  function(){$(this).toggleClass('hover')}
    			).click(function(){
    			  showOption(this, options);
    			});

  				// Focus on new value field.
  				$(this).parent().parent().next("tr.filedetails").find("input.newvalue").get(0).focus();
  				$(this).parent().parent().next("tr.filedetails").find("input.newvalue").get(0).select();
				
  				// Hide one diamond, show the other.
  				$(this).hide();
    			$(this).next().show();
    		}
      });
    });
  };
  function showOption(obj, options) { // Shows a selection from the file details menu.
    var section = $(obj).attr('class').replace('hover', '').replace(' ', '');
		var act = $(obj).parent().parent().find("input.act");
		var newval = $(obj).parent().parent().find("input.newvalue");
		var file = $(obj).parent().parent().find("input.file").val();
		var label = $(obj).parent().parent().find("label");
		var submit = $(obj).parent().parent().find("input.submit");
		// Un-select all <li>
		$(obj).parent().find("li").removeClass("selected");
		$(obj).addClass("selected");
		// Show/hide the new value field and change the text of the submit button.
		if (section.match('rename') || section.match('move') || section.match('duplicate') || section.match('chmod') || section.match('symlink')) {
			// Show new value field.
			newval.show();
			label.empty();
			submit.show();
			if (section.match('rename')) {
				label.append(options.rename);
				newval.val(file);
    		act.val('rename');
			} else if (section.match('move')) {
				label.append(options.move);
				newval.val("");
    		act.val('move');
			} else if (section.match('duplicate')) {
				label.append(options.duplicate);
				if (file.indexOf(".") != -1) {
					newval.val(file.substring(0, file.lastIndexOf("."))+"(copy)"+file.substr(file.lastIndexOf(".")));
				} else {
					newval.val(file+"(copy)");
				}
    		act.val('duplicate');
			} else if (section.match('chmod')) {
				label.append(options.chmod);
				newval.val($(obj).parents('tr').prev().find('td.details span.show').attr('class').match(/perm-[0-9]../).toString().substr(5));
    		act.val('chmod');
			} else if (section.match('symlink')) {
				label.append(options.symlink);
				if (file.indexOf(".") != -1) {
					newval.val(file.substring(0, file.lastIndexOf("."))+"(link)"+file.substr(file.lastIndexOf(".")));
				} else {
					newval.val(file+"(link)");
				}
    		act.val('symlink');
			}
			submit.val(options.ok);
			// Set focus on new value field.
			newval.get(0).focus();
			newval.get(0).select();
		} else if (section.match('del')) {
			// Hide new value field.
			newval.hide();
			label.empty();
			if (!$(obj).parents('tr.filedetails').prev().find('td.details span.show').eq(0).hasClass('empty') && $(obj).parents('tr.filedetails').prev().find('td.details span.show').eq(0).hasClass('dir')) {
  			label.append(options.del_warning);
  			submit.hide();
			} else {
  			label.append(options.del);
			}
			submit.val(options.del_button);
  		act.val('delete');
		} else if (section.match('unzip')) {
  		// Hide new value field.
  		newval.hide();
  		label.empty();
  		label.append(options.unzip);
  		submit.val(options.unzip_button);
  		submit.show();
  		act.val('unzip');
    } else {
      // See if plugin has defined this section.
      if (options.fileactions[section]) {
        if (options.fileactions[section].type == 'sendoff') {
           // Simple sendoff. Hide new value field.
           newval.hide();
           label.empty();
           label.append(options.fileactions[section].text);
           submit.val(options.fileactions[section].button)
           act.val(section);
        }
      }
    }
	};
	/** 
   * Search functions.
   **/
  $.fn.ft_search = function(options) {
    return this.each(function() {
  		$("#searchform").submit(function(){
  		  $("#dosearch").click();
  			return false;
  		});
      $("#dosearch").click(function(){
  			$("#searchresults").empty();
  			$("#searchresults").prepend("<h3>"+options.header+"</h3>").append("<dl id='searchlist'><dt class='error'>"+options.loading+"</dt></dl>");
  			$.post(options.formpost, {method:'ajax', act: 'search', q:$("#q").val(), type: $("#type").is(":checked"), dir:options.directory}, function(data){
  				$("#searchlist").empty();
  				$("#searchlist").append(data);
  				return false;
  			});
  			return false;
      });      
    });
  };
  

})(jQuery);</script><?php ft_make_scripts();?>

  <script type="text/javascript" charset="utf-8">
	$(document).ready(function(){
		// Set focus on login username.
		if (document.getElementById("ft_user")) {
			document.getElementById("ft_user").focus();
		}
		// Set global object.
		var ft = {fileactions:{}};
		// Prep upload section.
		$('#uploadsection').parent().ft_upload({
		  header:"<?php echo t('Files for upload:');?>", 
		  cancel: "<?php echo t('Cancel upload of this file');?>", 
		  upload: "<?php echo t('Now uploading files. Please wait...');?>"
		});
		// Prep file actions.
		$('#filelist').ft_filelist({
		  fileactions: ft.fileactions,
		  rename_link: "<?php echo t('Rename');?>",
		  move_link: "<?php echo t('Move');?>",
		  del_link: "<?php echo t('Delete');?>",
		  duplicate_link: "<?php echo t('Duplicate');?>",
		  unzip_link: "<?php echo t('Unzip');?>",
		  chmod_link: "<?php echo t('chmod');?>",
		  symlink_link: "<?php echo t('Symlink');?>",
		  rename: "<?php echo t('Rename to:');?>",
      move: "<?php echo t('Move to folder:');?>",
      del: "<?php echo t('Do you really want to delete file?');?>",
      del_warning: "<?php echo t('You can only delete empty folders.');?>",
      del_button: "<?php echo t('Yes, delete it');?>",
      duplicate: "<?php echo t('Duplicate to file:');?>",
      unzip: "<?php echo t('Do you really want to unzip file?');?>",
      unzip_button: "<?php echo t('Yes, unzip it');?>",
      chmod: "<?php echo t('Set permissions to:');?>",
      symlink: "<?php echo t('Create symlink called:');?>",
		  directory: "<?php if (!empty($_REQUEST['dir'])) {echo $_REQUEST['dir'];}?>",
		  ok: "<?php echo t('Ok');?>",
		  formpost: "<?php echo ft_get_self();?>",
		  advancedactions: "<?php if (ADVANCEDACTIONS === TRUE) {echo 'true';} else {echo 'false';}?>"
		});

    <?php
    // Automatic version checking.
    if (AUTOUPDATES != "0" && !empty($_SESSION['ft_user_'.MUTEX])) {
    ?>
      // Check if cookie is set - if not make update check.
      if ($.cookie('ft_update') == null) {
        // Time for an update.
  			$.post("<?php echo ft_get_self();?>", {method:'ajax', act:'versioncheck'}, function(data){
  				$("<div class=\"section\" id=\"autoupdate\"><h2>Checking for update</h2><div>"+data+"<button type=\"button\" id=\"dismiss\" class=\"info\"><?php echo t('Dismiss');?></button></div></div>").insertBefore('#status').slideDown().find('#dismiss').click(function() {
  				  $('#autoupdate').slideUp();
            // Set cookie.
            $.cookie('ft_update', '1', {expires: 1});
  				});
  			});
      }
    <?php
    }
    ?>
		// Manual version check.
		$("#versioncheck").click(function(){
			if ($("#versioninfo").css("display") == "block") {
				$("#versioninfo").hide("slow");
			} else {
				$("#versioninfo").empty();
				$.post("<?php echo ft_get_self();?>", {method:'ajax', act:'versioncheck'}, function(data){
					$("#versioninfo").empty().append(data).show("slow");
				});
			}
			return false;
		});
		// Sort select box.
		$('#sort').change(function(){
		  $('#sort_form').submit();
		});
		// Label highlight in 'create' box.
    $('#new input[type=radio]').change(function(){
      $('label').removeClass('label_highlight');
      $('label[@for='+$(this).attr('id')+']').addClass('label_highlight');      
    });
<?php echo implode("\r\n", ft_invoke_hook('add_js_call'));?>
	});
	</script>
	<style type="text/css">
	  .safarihide {
	position:absolute;
	left:-10000px;
}
body {
	font-family:Verdana, sans-serif;
	font-size:12px;
	color:<?php echo COLOURTEXT;?>;
	background:<?php echo COLOURONETEXT;?>;
}
body, h1, h2, .navigation, #sidebar form #sidebar #files_list, #filelist .filedetails form, #filelist .filedetails ul, #logout {
	margin:0;
	padding:0;
}
#filelist .details span.hide {
	background:<?php echo COLOURHIGHLIGHT;?>;
	color:<?php echo COLOURTEXT;?>;  
}
#filelist tr.rowhover, a:hover, h1, #sidebar h2, #filelist th, #filelist tfoot td, #filelist .hover, #filelist tr.rowhover .details span.hide {
	background:<?php echo COLOURONE;?> !important;
	color:<?php echo COLOURONETEXT;?> !important;
}
.error {color:red;}
.ok {color:<?php echo COLOURONE;?>;}
.hidden {display:none;}
a {
	color:<?php echo COLOURONE;?>;
	text-decoration:none;
}
a:hover {
	text-decoration:underline;
}
#logout {
	position:absolute;
	top:4px;
	right:4px;
	left:auto;
	bottom:auto;
	color:<?php echo COLOURONETEXT;?>;	
	text-align:right;
}
#logout p {
  margin:0;
}
h1 a, #logout a {
	color:<?php echo COLOURONETEXT;?>;
}
h1 {
	font-size:2em;
	font-weight:bold;
	padding:0.2em;
	margin-bottom:25px;
}
h2 {
	font-size:1.5em;
	font-weight:normal;
	margin-left:265px;
}
#main h2,
#main p {
  margin-left:25px;
}
form .description {
  font-size:0.8em;
  margin:0;
}
/* Normal tables */
table {
  border:1px solid black;
  border-collapse:collapse;
  margin:0 25px 15px 25px;
  text-align:left;
  width:300px;
}
th {
  font-weight:bold;
  background:<?php echo COLOURONE;?>;
  color:<?php echo COLOURONETEXT;?>;
}
th, td {
  border:1px solid black;
  padding:5px 10px;
}

/* Sidebar */
#sidebar {
	width:225px;
	margin:0 40px 0 25px;
	float:left;
	font-size:10px;
}
#sidebar .section {
	background:<?php echo COLOURTWO;?>;
	margin:0 0 2.5em 0;
	padding-bottom:0.8em;
	border:1px solid black;
}
#sidebar .section form {
	padding:0.8em 0.8em 0 0.8em;
}
#sidebar h2 {
	font-size:1.2em;
	font-weight:bold;
	padding:0.4em 0 0.4em 0.4em;
	margin:0;
	border-bottom:1px solid black;
}
#sidebar h3 {
	font-weight:bold;
	font-size:1.2em;
	margin:1em 0 0.5em 0;
}
#sidebar ul {
	margin:0.8em 0 0 1.5em;
	padding:0;	
}
#sidebar #files_list, #sidebar #searchlist {
	margin-left:1.5em;
}
#sidebar #uploadbutton {
	margin:1em 0 0 0;
}
#sidebar .info {
  float:right;
}
#files_list span.error {
	cursor:pointer;
}
#files_list span.error:hover {
	text-decoration:underline;
}
#uploadsection input {
	width:200px;
}
#mkdir, #q {
	width:140px;
}
#mkdirsubmit, #searchsubmit {
	width:40px;
}
#q {
	width:130px;
}
#searchsubmit {
	width:50px;
}
#sidebar p {
	text-align:center;
}
.label_highlight {
  font-weight:bold;
}
/* Search */
div#searchoptions {
	margin:0.5em 0 0 0.3em;
}
dl#searchlist dt {
	font-size:1.2em;;
}
dl#searchlist dt.dir {
	font-weight:bold;
}
dl#searchlist dd {
	margin:0.3em 0 0.5em 1em;
	padding-left:0;
}
dl#searchlist dd a {
	color:#666;
}
dl#searchlist dd a:hover {
	color:<?php echo COLOURONETEXT;?>;
}
/* Status box and auto update box */
#status p, #autoupdate p {
  text-align:left;
}
#status p, 
#status ul, 
#autoupdate div {
	text-align:left;
	margin:0px;
  padding:0;
}
#status ul {
	padding:0 0 0 10px;  
}
#status, #autoupdate {
	background-color:<?php echo COLOURHIGHLIGHT;?>;
	border:1px solid black;
	padding:10px;
	margin:0 0 15px 285px;
	width:400px;
}
/* File list */
#filelist td.name a {
	color:<?php echo COLOURTEXT;?>;
  display:block;
/*  width:100%;*/
/*  height:100%;*/
  padding:4px 2em 4px 10px;
}
#filelist td.name {
  padding:0;
  margin:0;
}
#filelist a:hover {
	background:inherit;
	text-decoration:none;
}
#filelist tr.rowhover a {
	color:<?php echo COLOURONETEXT;?>;
}
#filelist {
	border:1px solid black;
	border-collapse:collapse;
	margin:0 25px;
}
#filelist tfoot td, #filelist th {
	border-top:1px solid black;
	border-bottom:1px solid black;
}
#filelist th, #filelist tfoot td {
	font-weight:bold;
}
#filelist th.size a {
	color:white;
}
#filelist th {
	padding:0.3em 0.6em;
	text-align:left;
}
#filelist td.details {
  padding:0.3em 0;
}
#filelist .details span.show, #filelist .details span.hide {
	cursor:pointer;
  padding:4px 4px;
}
#filelist th.size, 
#filelist td.size, 
#filelist th.date, 
#filelist td.date {
	text-align:right;
}
#filelist th.size, 
#filelist td.size {
  padding-right:10px;
}
#filelist tfoot td {
	font-size:10px;
	text-align:right;
	font-weight:normal;
}
#filelist tr {
	background:<?php echo COLOURONETEXT;?>;
}
#filelist tr.odd {
	background:<?php echo COLOURTWO;?>;
}
#filelist tr.dir td.name {
	font-weight:bold;
}
#filelist tr.highlight {
	background:<?php echo COLOURHIGHLIGHT;?>;
	font-style:italic;
	font-weight:bold;
}
#filelist tr.rowhover {
	background:<?php echo COLOURONE;?>;
	color:<?php echo COLOURONETEXT;?>;
}
#filelist .hover, #filelist .filedetails ul li {
	cursor:pointer;
}
#filelist .filedetails {
	background:<?php echo COLOURHIGHLIGHT;?>;
	font-size:10px;
	border-top:2px solid black;
	border-bottom:2px solid black;
	padding:1em 0.5em;
}
#filelist .filedetails td {
	width:275px;
}
#filelist .filedetails .newvalue {
	width:150px;
}
#filelist .filedetails form {
	padding:0.3em;
}
#filelist .filedetails label {
	display:block;
	font-weight:bold;
	margin:0 0 0.5em 0;
}
#filelist .filedetails ul {
	list-style:none;
	padding:0.3em 1.2em 0.3em 0.3em;
	width:60px;
	float:left;
}
#filelist .filedetails ul li.selected {
	font-weight:bold;
}
#filelist td.error {
	padding:1em 3em;
}
form#sort_form {
  margin:0;
  padding:0;
  float:right;
}
#sort {
  margin:0;
  padding:0;
}
/* Edit form */
form#edit, #main {
/*  margin-left:265px;*/
float:left;
}
form#edit textarea {
	margin:1.5em 0 1em 0;
}
#savestatus {
	margin-left:265px;
}
/* Login box */
#loginbox {
	margin:25px;
	width:350px;
}
#loginbox div {
  clear:both;
}
#loginbox label {
  display:block;
  height:2.4em;
  width:100%;
}
#cookie_label {
  text-align:left;
  margin-left:116px;
}
#ft_user, #ft_pass {
  float:right;
  width:225px;
}
#login_button {
  float:right;
}
/* Footer */
#footer {
	font-size:10px;
	clear:both;
	margin:25px;
	padding-bottom:50px;
}
.seperator {
	border-top:2px solid <?php echo COLOURONE;?>;
}
#versioninfo {
	display:none;
	margin:1em 2em;
	padding:0.5em;
	border:2px solid <?php echo COLOURONE;?>;
	background:<?php echo COLOURHIGHLIGHT;?>;
	width:250px;
}
    <?php echo implode("\r\n", ft_invoke_hook('add_css'));?>
	</style>
</head>
<body>
  
	<?php echo $str;?>
  <?php echo ft_make_scripts_footer();?>
  <?php echo implode("\r\n", ft_invoke_hook('destroy'));?>
</body>
</html>