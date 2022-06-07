<?php
$server = "localhost:3306";
$user = "root";
$pwd = "";
$db = "users";

// $conn = new mysqli($server, $user, $pwd, $db);
$conn = mysqli_connect($server, $user, $pwd, $db);

header("Content-Type: text/html");
if($conn->connect_errno)
{
    http_response_code(400);
    echo  $conn->connect_error; 
    exit();
}
else{
    echo "Database connection successful";
}
