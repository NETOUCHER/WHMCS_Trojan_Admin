<?php

/**
 * @author Gaukas
 * @version 1.0.0
**/

// READ ME
// This version is not compatible with the former version. The database structure is completely different.

use WHMCS\Database\Capsule;

/* Needs to be enabled after debugging */
if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}


function TrojanAdmin_MetaData()
{
    return array(
        'DisplayName' => 'Trojan Admin',
        'APIVersion' => '1.1', // Use API Version 1.1
        'RequiresServer' => false, 
    );
}

function TrojanAdmin_ConfigOptions() {
	return [
		/****** Additional Work Required for QR Code Supports ******/
		/****** Trojan Configuration ******/
		"product_name" => [
			"FriendlyName" => "Product Name", 
			"Type" => "text",
			"Size" => "25",
			"Description" => "Required. Must match with only one product in product_JSON.php",
		],
		"allow_insecure" => [				// $allow_insecure = $params['configoption2'];
			"FriendlyName" => "Allow Insecure", 
			"Type" => "yesno",    
			"Description" => "Allow Insecure",
		],
		"peer_name" => [
			"FriendlyName" => "Peer Name", 
			"Type" => "text",
			"Size" => "25",
			"Description" => "Optional, used when common name in certs is not hostname",
		],
		"obfuscation" => [
			"FriendlyName" => "Obfuscation", 		
			"Type" => "dropdown",
			"Options" => "none,websocket",
			"Description" => "Obfuscation module used for trojan protocol.",
			"Default" => "none",
		],
		"muxing" => [
			"FriendlyName" => "Muxing", 
			"Type" => "yesno",    
			"Description" => "Enable Muxing",
		],
		"plugin" => [
			"FriendlyName" => "Plugin", 
			"Type" => "text",
			"Size" => "25",
			"Description" => "Optional plugin",
			"Default" => "none",
		],		
		"fast_open" => [
			"FriendlyName" => "Fast Open", 
			"Type" => "yesno",    
			"Description" => "Enable TCP Fastopen",
		],
		"traffic" => [			// $traffic = $params['configoption8'];
			"FriendlyName" => "Default Traffic(GB) per billing", 
			"Type" => "text",
			"Size" => "25",
			"Description" => "Default bandwidth if not specified by configurable options",
			"Default" => "10",
		],
	];
}

function TrojanAdmin_ParseJSON() {
	$str = file_get_contents('/home/secured_dir/products_JSON.php');
	$json = json_decode($str, true); // decode the JSON into an associative array
	return $json;
}

function TrojanAdmin_CreateAccount($params) {
	$serviceid			= $params["serviceid"]; //The unique ID of the product in WHMCS database.
  	$password 			= $params["password"];

	// Use WHMCS Capsule to get adminusername for API
	$pdo = Capsule::connection()->getPdo();
	$pdo->beginTransaction();
	try {
		$stmt = $pdo->query("SELECT username FROM tbladmins");
		$adminusername = $stmt->fetch(PDO::FETCH_ASSOC);
		$pdo->commit();
	} catch (\Exception $e) {
		$pdo->rollBack();
		return "Got error when trying to get adminusername {$e->getMessage()}";
	}
	
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file. <br>".$product_name."<br><pre>".print_r($product_json, true)."</pre>";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		// Build PDO_MySQL Object
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
		$attr = array(
			PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);
		// Check to make sure no repeated service.
		try
		{
			$pdo2 = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt2 = $pdo2->prepare('SELECT pid FROM users WHERE pid=:serviceid');
			$stmt2->execute(array(':serviceid' => $serviceid));
			$select = $stmt2->fetch(PDO::FETCH_ASSOC);
		}
		catch(PDOException $e){
			return 'Cannot check pid.' . $e->getMessage();
		}

		if (!empty($select['pid'])) {
			$result = "Service already exists in ".$db_name;
			return $result;
	  	} else {
			// Handle password customization
			if (isset($params['customfields']['password'])) {
				$command = 'EncryptPassword';
				$postData = array(
				  'password2' => $params["customfields"]['password'],
				);
				try {
					$adminuser = $adminusername['username'];
				} catch (Exception $e) {
					die("Failure in adminuser define. No username in the ARRAY adminusername could be found.");
				}
				$adminuser = $adminusername['username'];
				$results = localAPI($command, $postData, $adminuser);
				$table = 'tblhosting';
				try {
				$updatedUserCount = Capsule::table($table)
				->where('id', $params["serviceid"])
				->update(
				  [
					'password' => $results['password'],
					  ]
				);
				} catch (\Exception $e) {
				echo "Password update failed.Bad Capsule function. {$e->getMessage()}";
				}
				$password = $params["customfields"]['password'];
			} elseif (strpos($password,'#')!==false) {
				# TODO: Filter out all #'s in $password
				
			}
			// Hash the final password
			$password2submit = hash("sha224", $password);
			// Handle Traffic
			if(isset($params['configoptions'][$prop['traffic_option']]))
			{
				$traffic_GB = $params['configoptions'][$prop['traffic_option']];
				$traffic = $traffic_GB*1024*1024*1024; // In Bytes
				$stmt3 = $pdo2->prepare("INSERT INTO users(password,quota,pid) VALUES (:password,:traffic,:serviceid)");

				if($stmt3->execute(array(':password'=>$password2submit, ':traffic'=>$traffic, ':serviceid'=>$params['serviceid'])))
				{
					$result = 'success';
				}
				else
				{
					$result='Error in creating traffic customized user in '.$prop['mysql_database'];
					return $result;
				}
			}
			else
			{	
				// If not set for specific server, then read the product-wise preset.
				if (!empty($params['configoption8']))
				{
					$max = $params['configoption8'];
				}
				if(isset($max))
				{
					$traffic = $max*1024*1048576; // GB -> B
				} else {
					$traffic = -1; // Unlimited
				}
	
				$stmt3 = $pdo2->prepare("INSERT INTO users(password,quota,pid) VALUES (:password,:traffic,:serviceid)");
				if($stmt3->execute(array(':password'=>$password2submit, ':traffic'=>$traffic, ':serviceid'=>$params['serviceid'])))
				{
						$result='success';
				}
				else
				{
						$result = 'Error. Could not Creat Account for preset traffic user in '.$prop['mysql_database'];
						return $result;
				}
			}
		}
	}
  	return $result;
}

function TrojanAdmin_TerminateAccount($params) {
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;

		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);

		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare('DELETE FROM users WHERE pid=:serviceid');
			if($stmt->execute(array(':serviceid' => $params['serviceid'])))
			{
				$result = 'success';
			} else {
				$result = 'Error. Could not Terminate this Account in '.$db_name;
				return $result;
			}
		}
		catch(PDOException $e){
			$result = 'PDO error:' . $e->getMessage()." in ".$db_name;
			return $result;
		}
	}
	return $result;
}

function TrojanAdmin_SuspendAccount($params) {
	$username = $params['serverusername'];
	$pwd = $params['serverpassword'];
	
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
		
		$attr = array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION);

		$password = md5(time().rand(0,100));
		// Hash the final password
		$password = hash("sha224", $password);
		try{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare("SELECT pid FROM users WHERE pid=:serviceid");
			if($stmt->execute(array(':serviceid' => $params['serviceid'])))
			{
			$select = $stmt->fetch(PDO::FETCH_ASSOC);
			}
		}catch(PDOException $e){
			$result = 'Error. PDO error in select this account in '.$db_name;
			return $result;
		}

		if ($select == "")
		{
			$result = "Can't find the account in ".$db_name;
			return $result;
		}
		else
		{
			try
			{
				$stmt = $pdo->prepare("UPDATE users SET password=:passwd WHERE pid=:serviceid");
				if($stmt->execute(array(':passwd' => $password, ':serviceid' => $params['serviceid'])))
				{
					$result = 'success';
				}
				else
				{
					$result="failed in ".$db_name;
					return $result;
				}
			}
			catch(PDOException $e)
			{
				die('Error. Cloud not Suspend this Account in '.$db_name. " with error ". $e->getMessage());
			}
		}
	}
	return $result;
}

function TrojanAdmin_UnSuspendAccount($params) {
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;

		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);

		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			//if ($params['password'] == $params['customfields']['password']) {
			$password = $params['password'];
			$password = hash("sha224", $password);
			//} else {
			//	$password = $params['customfields']['password'];
			//}
			$stmt = $pdo->prepare("SELECT pid FROM users WHERE pid=:serviceid");
			$stmt->execute(array(':serviceid' => $params['serviceid']));
			$select = $stmt->fetch(PDO::FETCH_ASSOC);
			if ($select == "") {
				$result = "Can't find service in ".$db_name;
				return $result;
			} else {
				$stmt = $pdo->prepare("UPDATE users SET password=:passwd WHERE pid=:serviceid");
				if($stmt->execute(array(':passwd' => $password, ':serviceid' => $params['serviceid'])))
				{
					$result = 'success';
				}	
				else
				{
					$result="failed to execute unsuspension in ".$db_name;
					return $result;
				}
			}
		}
		catch(PDOException $e){
			die('Cannot UnSuspendAccount. PDO Exception in '.$db_name. $e->getMessage());
		}
	}
	return $result;
}

function TrojanAdmin_ChangePassword($params) {
	$password = $params['password'];
	$password = hash("sha224", $password);
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
	
		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);

		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare("SELECT pid FROM users WHERE pid=:serviceid");
			$stmt->execute(array(':serviceid' => $params['serviceid']));
			$select = $stmt->fetch(PDO::FETCH_ASSOC);
			if ($select == "") {
				$result = "Can't find.";
				return $result;
			} else {
				$stmt = $pdo->prepare("UPDATE users SET password=:passwd WHERE pid=:serviceid");
				$stmt->execute(array(':passwd' => $password, ':serviceid' => $params['serviceid']));
				$result = "success";
			}
		}
		catch(PDOException $e){
			die('Update userpassword Failed in ChangePassword' . $e->getMessage());
		}
		// if ($result=="success")
		// {
		// 	$pdo2 = Capsule::connection()->getPdo();
		// 	$pdo2->beginTransaction();
		// 	try {
		// 	$statement = $pdo2->query('SELECT id FROM tblcustomfields WHERE fieldname=Password');//Editable 'Password'
		// 	$data = $statement->fetch(PDO::FETCH_ASSOC);
		// 	$pdo2->commit();
		// 	} catch (\Exception $e) {
		// 	echo "Error when ChangePassword by WHMCS PDO {$e->getMessage()}";
		// 	$pdo2->rollBack();
		// 	return "Rolling Back Changes";
		// 	}
		// 	$fieldid = $data['id'];
		// 	$table = 'tblcustomfieldsvalues';
		// 	try {
		// 		$updatePassword = Capsule::table($table)
		// 			->where('relid', $params["serviceid"])
		// 			->where('fieldid', $fieldid)
		// 			->update(
		// 				[
		// 					'value' => $params["password"],
		// 				]
		// 			);
		// 	} catch (\Exception $e)  {
		// 		echo "Password reset failed in ChangePassword.Bad Capsule function. {$e->getMessage()}";
		// 		return $result;
		// 	}
		// 	$result = 'success';
		// } else {
		// 	echo $result;
		// 	return $result;
		// }
	}
	return $result;
}

function TrojanAdmin_ChangePackage($params) {
	$password = $params['password'];
	$password = hash("sha224", $password);
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
	
		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);

		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			if(isset($params['configoptions'][$prop['traffic_option']])) {
				$traffic_GB = $params['configoptions'][$prop['traffic_option']];
				$traffic = $traffic_GB*1024*1048576;
				$stmt = $pdo->prepare("UPDATE users SET quota=:traffic WHERE pid=:serviceid");
				$stmt->execute(array(':traffic' => $traffic, ':serviceid' => $params['serviceid']));
				//return 'success';
			} else {
				if (!empty($params['configoption8'])) {
					$max = $params['configoption8'];
				}
				if(isset($max)) {
					$traffic = $max*1024*1048576;
				} else {
					$traffic = -1;
				}
				$stmt = $pdo->prepare("UPDATE users SET quota=:traffic WHERE pid=:serviceid");
				$stmt->execute(array(':traffic' => $traffic, ':serviceid' => $params['serviceid']));
				//return 'success';
			}
		}
		catch(PDOException $e){
			die('Update usertransfer Failed in ChangePackage'.$db_name . $e->getMessage());
		}
	}
	return 'success';
}

function TrojanAdmin_Renew($params) {
  $result = TrojanAdmin_RstTraffic($params);
  //$result = TrojanAdmin_AddTraffic($params);
  switch ($result){
    case 'success':
      return 'success';
    case false:
      return 'Failed to execute PDO SQL query to reset/add traffic. Check the database.';
    default:
      return $result;
	}
}

//The function RstTraffic will operate the database as setting the upload and download traffic to zero.
function TrojanAdmin_RstTraffic($params) {
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;

		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);

		if(isset($params['configoptions'][$prop['traffic_option']]))
		{
			$traffic_GB = $params['configoptions'][$prop['traffic_option']];
			$traffic = $traffic_GB*1024*1048576;
		}
		else
		{
			if (!empty($params['configoption8']))
			{
				$traffic = $params['configoption8']*1024*1048576;
			} 	
			else
			{
				$traffic = 53687091200;
			}
		}

		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare("UPDATE users SET download='0',upload='0',quota=:traffic WHERE pid=:serviceid");
			if($stmt->execute(array(':traffic' => $traffic, ':serviceid' => $params['serviceid']))){
				//return 'success';
			}
			else {
				return false;
			}
		}
		catch(PDOException $e){
			die('PDO Error occurred in resetting traffic' . $e->getMessage());
		}
	}
	return 'success';
}
// Unfinished.
// function TrojanAdmin_AddTraffic($params) {
// 	$db_server = $params['configoption1'];
// 	$db_port = $params['configoption2'];
// 	$db_name = $params['configoption3'];
// 	$db_charset = $params['configoption4'];
// 	$db_user = $params['configoption5'];
// 	$db_pwd = $params['configoption6'];
// 	$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
	
// 	$attr = array(
// 			PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
// 	);

//   	if(isset($params['configoptions']['Traffic']))
//   	{
//     	$traffic_GB = explode("G",$params['configoptions']['Traffic'])[0];
//     	$traffic = $traffic_GB*1024*1048576;
//   	}
//   	else
//   	{
//     	if (!empty($params['configoption10']))
//     	{
//       		$traffic = $params['configoption10']*1024*1048576;
// 		} 	
// 		else
// 		{
//     		$traffic = 53687091200;
//     	}
//   	}

// 	try
// 	{
// 		$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
// 		$stmt = $pdo->prepare("UPDATE `user` SET `transfer_enable`=`transfer_enable`+:traffic WHERE `pid`=:serviceid");
// 		if($stmt->execute(array(':traffic' => $traffic, ':serviceid' => $params['serviceid']))){
// 			return 'success';
// 		}
// 		else {
// 			return false;
// 		}
// 	}
// 	catch(PDOException $e){
// 		die('PDO Error occurred in adding traffic' . $e->getMessage());
// 	}
// }

// function TrojanAdmin_RefrePort($params) {
// 	$db_server = $params['configoption1'];
// 	$db_port = $params['configoption2'];
// 	$db_name = $params['configoption3'];
// 	$db_charset = $params['configoption4'];
// 	$db_user = $params['configoption5'];
// 	$db_pwd = $params['configoption6'];
// 	$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
	
// 	$attr = array(
// 			PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
// 	);

// 	try
// 	{
// 		$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
// 		$stmt = $pdo->prepare("SELECT u,d,port,passwd,transfer_enable FROM users WHERE pid=:serviceid");
// 		$stmt->execute(array(':serviceid' => $params['serviceid']));
// 		$Query = $stmt->fetch(PDO::FETCH_BOTH);
// 		$u = $Query['u'];
// 		$d = $Query['d'];
// 		$passwd = $Query['passwd'];
// 		$traffic = $Query['transfer_enable'];
// 		$port = $Query['port'];
//     	$nextport = TrojanAdmin_NextPort($params);

// 		if($nextport==0){
// 			return 'Sorry, next port exceeded.'; //If this is the last port, refuse the refresh request to prevent abuse.
// 		}

// 		// if($port==$nextport-1){
// 		//   return 'Sorry, this is a new port and is not eligible for refresh.'; //If this is the last port, refuse the refresh request to prevent abuse.
// 		// }

// 		$terminate=TrojanAdmin_TerminateAccount($params);
// 		if($terminate!='success')
// 		{
// 			return $terminate;
// 		}

// 		$stmt3 = $pdo->prepare("INSERT INTO user(u,d,port,passwd,transfer_enable,pid) VALUES (:u,:d,:port,:password,:traffic,:serviceid)");
// 		if($stmt3->execute(array(':u'=>$u, ':d'=>$d, ':port'=>$nextport, ':password'=>$passwd, ':traffic'=>$traffic, ':serviceid'=>$params['serviceid'])))
// 		{
// 			return 'success';
// 		}
// 		else
// 		{
// 			return 'Failed to refresh port. An error rather than PDO error occurred.';
// 		}
//   	}
//   	catch(PDOException $e){
//     	die('PDO Error occurred.'.$e->getMessage());
//   	}
// }

//The function to divide every node by the character ';' and output as a node for each line in HTML (devide with <br>)
function TrojanAdmin_node($params) {
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;

		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);
		
		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare("SELECT quota FROM users WHERE pid=:serviceid");
			$stmt->execute(array(':serviceid' => $params['serviceid']));
			$query = $stmt->fetch(PDO::FETCH_BOTH);
			if($query['quota']!=-1) {
				$traffic = $query['quota'] / 1073741824;
				$free = $traffic - $usage;
				$traffic = round($traffic,2);
			} else {
				$traffic = NULL;
			}

			if( !isset($traffic) || $traffic!=0 ) {
				$html .= $prop['server_addr'].":".$prop['server_port']."<br>";
			}
		}
		catch(PDOException $e){
			$html .= "[!node]".$e->getMessage()."<br>";
		}
	}
	return $html;
}
//Show the SS link as ss://{method[-auth]:password@hostname:port} (the string in {} was encrypted by base64)
function TrojanAdmin_link($params) {
	$password = $params['password'];
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;

		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);
		
		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare("SELECT quota FROM users WHERE pid=:serviceid");
			$stmt->execute(array(':serviceid' => $params['serviceid']));
			$query = $stmt->fetch(PDO::FETCH_BOTH);
			if($query['quota']!=-1) {
				$traffic = $query['quota'] / 1073741824;
				$free = $traffic - $usage;
				$traffic = round($traffic,2);
			} else {
				$traffic = NULL;
			}

			if( !isset($traffic) || $traffic!=0 ) {
				$originalcode=$password."@".$prop['server_addr'].":".$prop['server_port'];
				// $originalcode .= "#".$prop['friendly_name'];
				$output .= 'trojan://'.$originalcode.'<br>';
			}
		}
		catch(PDOException $e){
			$output .= "[!link]".$e->getMessage()."<br>";
		}
	}
	return $output;
}

function TrojanAdmin_qrcode($params) {
	$password = $params['password'];
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;

		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);
		
		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare("SELECT quota FROM users WHERE pid=:serviceid");
			$stmt->execute(array(':serviceid' => $params['serviceid']));
			$query = $stmt->fetch(PDO::FETCH_BOTH);
			if($query['quota']!=-1) {
				$traffic = $query['quota'] / 1073741824;
				$free = $traffic - $usage;
				$traffic = round($traffic,2);
			} else {
				$traffic = NULL;
			}

			if( !isset($traffic) || $traffic!=0 ) {
				$originalcode=$password."@".$prop['server_addr'].":".$prop['server_port'];
				// $originalcode .= "%23".$prop['friendly_name'];
				$output = 'trojan://'.$originalcode;
				$imgs .= '<img src="https://example.com/modules/servers/TrojanAdmin/lib/QR_generator/qrcode.php?text='.$output.'" style="align=:center;" />&nbsp;';
			}
		}
		catch(PDOException $e){
			$imgs .= "[!img]".$e->getMessage()."<br>";
		}
	}
  	return $imgs;
}

function TrojanAdmin_ClientArea($params) {
	$password = $params['password'];
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}

	$node = TrojanAdmin_node($params);
	$trojlink = TrojanAdmin_link($params);
	$trojqr = TrojanAdmin_qrcode($params);

	$html .= "
	<div class=\"row\">
		<div class=\"col-md-12\">
			<a class=\"btn btn-default\" role=\"button\" data-toggle=\"collapse\" href=\"#collapseExample\" aria-expanded=\"true\" aria-controls=\"collapseExample\">QR code</a>
			<div style=\"margin-top: 10px;\" class=\"collapse in\" id=\"collapseExample\" aria-expanded=\"true\">
  				<div class=\"well\" style=\"text-align:center;word-break:break-all; word-wrap:break-all;\">
    					{$trojqr}
					<br>
    					{$trojlink}
  				</div>
			</div>
		</div>
  		<div style=\"text-align:center;margin-top:35px;\" class=\"col-md-3\">
    			<i class=\"fa fa-server fa-4x\"></i>
      			<h3>Server</h3>
      			<kbd>{$node}</kbd>
      		</div>
  		<div style=\"text-align:center;margin-top:35px;\" class=\"col-md-3\">
   			<i class=\"fa fa-key fa-4x\"></i>
      			<h3>Password</h3>
      			<kbd>{$password}</kbd>
      		</div>
	</div>
	";


	// Looping through the json, configure each product
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
	
		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);

		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			#$traffic = $params['configoptions']['Traffic'];
			$stmt = $pdo->prepare("SELECT sum(download+upload),quota FROM users WHERE pid=:serviceid");
			$stmt->execute(array(':serviceid' => $params['serviceid']));
			$query = $stmt->fetch(PDO::FETCH_BOTH);
			$usage = $query[0] / 1073741824;
			if($query['quota']!=-1) {
				$traffic = $query['quota'] / 1073741824;
				$free = $traffic - $usage;
				$traffic = round($traffic,2);
			} else {
				$traffic = NULL;
			}
			$usage = round($usage,2);
			$free = round($free,2);
			$usagerate = $usage/$traffic*100;
			$freerate = $free/$traffic*100;
			$thisserver = $prop['friendly_name'];
			//debug
			// $decodeQuery = json_encode($query);
		}
		catch(PDOException $e){
				$html.=" 
				<div class=\"row\">
				<!--<div class=\"col-sm-4\">-->
				<!--<div class=\"panel-collapse collapse in\">-->

				<h3 style=\"color: #ffffff; background-color: #ff0000\"><strong>SERVICE OUT OF ORDER</strong></h3>

				<hr />

				<h4><strong>Feel free to contact our customer service if you don't think you should see this.</strong></h4>

				<hr />

				<h4style=\"color: #000000; background-color: #ffffff\"><strong>". $e->getMessage() ."</strong></h4>

				<hr />

				</div>
			<!--</div>-->
			";
		}

		if (isset( $traffic )) {
			if($traffic!=0) {
				$html .= "
				<br>
				<p>{$thisserver}</p>
				<div class=\"progress\" style=\"align=center;width=80%;\">
						<div role=\"progressbar\" aria-valuenow=\"60\" aria-valuemin=\"0\" aria-valuemax=\"100\" class=\"progress-bar progress-bar-warning\" style=\"width: {$usagerate}%;\">
						<span>Used {$usage} GB</span>
						</div>
						<div role=\"progressbar\" aria-valuenow=\"60\" aria-valuemin=\"0\" aria-valuemax=\"100\" class=\"progress-bar progress-bar-success\" style=\"width: {$freerate}%;\">
							<span>Balance {$free} GB</span>
						</div>
				</div>
					";
			}
		} else {
			$html .= "
			<br>
			<p>{$thisserver}</p>
			<div class=\"progress\" style=\"align=center;width=80%;\">
					</div>
					<div role=\"progressbar\" aria-valuenow=\"60\" aria-valuemin=\"0\" aria-valuemax=\"100\" class=\"progress-bar progress-bar-success\" style=\"width: {$freerate}%;\">
						<span>UNLIMITED: Used {$usage} GB</span>
					</div>
			</div>
			";
		}
	}
    return $html;
}

function TrojanAdmin_AdminServicesTabFields($params) {
	$fieldsarray = array();
	// Parse JSON config
	$product_json = TrojanAdmin_ParseJSON();
	// Reading product info from config.
	$product_name=$params['configoption1'];
	// Check if product JSON exist.
	if(!array_key_exists($product_name, $product_json)) {
		return "Product is not configured in JSON file.";
	}
	foreach ($product_json[$product_name] as $serv => $prop) {
		$db_server = $prop['mysql_server'];
		$db_name = $prop['mysql_database'];
		$db_port = $prop['mysql_port'];
		$db_charset = $prop['mysql_charset'];
		$db_user = $prop['mysql_user'];
		$db_pwd = $prop['mysql_passwd'];
		$dsn = "mysql:host=".$db_server.";dbname=".$db_name.";port=".$db_port.";charset=".$db_charset;
	
		$attr = array(
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		);

		try
		{
			$pdo = new PDO($dsn, $db_user, $db_pwd, $attr);
			$stmt = $pdo->prepare("SELECT sum(upload+download),quota FROM users WHERE pid=:serviceid");
			$stmt->execute(array(':serviceid' => $params['serviceid']));
			$Query = $stmt->fetch(PDO::FETCH_BOTH);
			$Used = round($Query[0]/1048576/1024,2);
			if($Query['quota']==-1) {
				$traffic=NULL;
			}
			else {
				$traffic = round($Query['quota'] / 1048576 / 1024,2);
			}			
			$Free = round($traffic - $Used,2);
			if(!isset($traffic) || $traffic!=0 ) {
				$tmp_arr = array($serv.'-Stats' => 'Free: '.$Free."/ Used: ".$Used."/ Total: ".$traffic);
				$fieldsarray += $tmp_arr;
			}
		}
		catch(PDOException $e){
				$fieldsarray = array(
				'Status' => 'ERROR',
				'Reason' => 'Failed to establish connection to database',
				'ErrMsg' => $e->getMessage(),
				);
				return $fieldsarray;
		}
	}
	return $fieldsarray;
}

function TrojanAdmin_AdminCustomButtonArray() {
  $buttonarray = array(
   "Reset Traffic" => "RstTraffic",
  );
  return $buttonarray;
}

?>
