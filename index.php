<?php
require __DIR__ . "/vendor/autoload.php";

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

define("COOKIE_NAME", "ivao_tokens");

$openid_url = "https://api.ivao.aero/.well-known/openid-configuration";
$openid_result = file_get_contents($openid_url);

if ($openid_result === false) {
    die("Error while getting openid data");
}

$openid_data = json_decode($openid_result, true);

$client_id = $_ENV["ivao_client_id"];
$client_secret = $_ENV["ivao_client_secret"];
$redirect_uri = $_ENV["ivao_redirect_uri"];

if (isset($_GET["code"]) && isset($_GET["state"])) {
    handleOAuth2Callback($openid_data, $client_id, $client_secret, $redirect_uri);
} elseif (isset($_COOKIE[COOKIE_NAME])) {
    handleUserSession($openid_data, $client_id, $client_secret, $redirect_uri);
} else {
    initiateOAuth2();
}

function handleOAuth2Callback($openid_data, $client_id, $client_secret, $redirect_uri) {
    $code = $_GET["code"];

    $token_req_data = [
        "grant_type" => "authorization_code",
        "code" => $code,
        "client_id" => $client_id,
        "client_secret" => $client_secret,
        "redirect_uri" => $redirect_uri,
    ];

    $token_options = [
        "http" => [
            "header" => "Content-type: application/x-www-form-urlencoded\r\n",
            "method" => "POST",
            "content" => http_build_query($token_req_data),
        ],
    ];

    $token_context = stream_context_create($token_options);
    $token_result = file_get_contents($openid_data["token_endpoint"], false, $token_context);

    if ($token_result === false) {
        die("Error while getting token");
    }

    $token_res_data = json_decode($token_result, true);
    $access_token = $token_res_data["access_token"];
    $refresh_token = $token_res_data["refresh_token"];

    setcookie(COOKIE_NAME, json_encode([
        "access_token" => $access_token,
        "refresh_token" => $refresh_token,
    ]), time() + 60 * 60 * 24 * 30);

    header("Location: " . $redirect_uri);
}

function handleUserSession($openid_data, $client_id, $client_secret, $redirect_uri) {
    $tokens = json_decode($_COOKIE[COOKIE_NAME], true);
    $access_token = $tokens["access_token"];
    $refresh_token = $tokens["refresh_token"];

    $user_options = [
        "http" => [
            "header" => "Authorization: Bearer $access_token\r\n",
            "method" => "GET",
            "ignore_errors" => true,
        ],
    ];

    $user_context = stream_context_create($user_options);
    $user_result = file_get_contents($openid_data["userinfo_endpoint"], false, $user_context);
    $user_res_data = json_decode($user_result, true);

    if (isset($user_res_data["description"]) && ($user_res_data["description"] === "This auth token has been revoked or expired" || $user_res_data["description"] === "Couldn't decode auth token")) {
        refreshToken($openid_data, $client_id, $client_secret, $redirect_uri, $refresh_token);
    } elseif (isset($user_res_data["description"]) && $user_res_data["description"] === "No auth token found in request") {
        setcookie(COOKIE_NAME, "", time() - 3600);
        header("Location: " . $redirect_uri);
    } else {
        if (is_divisional_staff($user_res_data["userStaffPositions"])) {
            displayUploader();
        } else {
            ?>


            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <link rel="icon" type="image/x-icon" href="/assets/logo.png">
                <title>Access Denied</title>
                <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            </head>
            <body class="bg-gray-100 flex items-center justify-center h-screen">
                <div class="max-w-md mx-auto bg-white rounded-lg shadow-lg overflow-hidden">
                    <div class="p-4">
                        <div class="text-center">
                            <h1 class="text-3xl font-bold text-red-600">Access Denied</h1>
                            <p class="mt-2 text-gray-600">Sorry, you do not have permission to access this page.</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            
            
            
                <?php        }
    }
}

function refreshToken($openid_data, $client_id, $client_secret, $redirect_uri, $refresh_token) {
    $token_req_data = [
        "grant_type" => "refresh_token",
        "refresh_token" => $refresh_token,
        "client_id" => $client_id,
        "client_secret" => $client_secret,
    ];

    $token_options = [
        "http" => [
            "header" => "Content-type: application/x-www-form-urlencoded\r\n",
            "method" => "POST",
            "content" => http_build_query($token_req_data),
            "ignore_errors" => true,
        ],
    ];

    $token_context = stream_context_create($token_options);
    $token_result = file_get_contents($openid_data["token_endpoint"], false, $token_context);

    if ($token_result === false) {
        die("Error while refreshing token");
    }

    $token_res_data = json_decode($token_result, true);
    $access_token = $token_res_data["access_token"];
    $refresh_token = $token_res_data["refresh_token"];

    setcookie(COOKIE_NAME, json_encode([
        "access_token" => $access_token,
        "refresh_token" => $refresh_token,
    ]), time() + 60 * 60 * 24 * 30);

    header("Location: " . $redirect_uri);
}

function is_divisional_staff($staffPositions) {
    foreach ($staffPositions as $position) {
        if ($position["divisionId"] === $_ENV["division_id"]) {
            return true;
        }
    }
    return false;
}

function displayUploader() {
    function convertToBytes($value) {
        $units = ["B", "K", "M", "G", "T", "P"];
        $value = trim($value);
        $last = strtoupper($value[strlen($value) - 1]);
        $value = (int) $value;
        $exponent = array_search($last, $units);
        return $value * pow(1024, $exponent);
    }

    $uploadMaxFilesize = ini_get("upload_max_filesize");
    $maxFileSizeBytes = convertToBytes($uploadMaxFilesize);
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Image Uploader</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <link rel="icon" type="image/x-icon" href="/assets/logo.png">
        <style>
            * {
                font-family: poppins;
            }
            .bg-blue-custom {
                background-color: #0D2C99;
            }
            .bg-blue-custom:hover {
                background-color: #0a237a;
            }
            .text-blue-custom {
                color: #0D2C99;
            }
            .border-blue-custom {
                border-color: #0D2C99;
            }
            .border-blue-custom:focus {
                border-color: #0a237a;
                box-shadow: 0 0 0 2px #C5CAE9;
            }
            #fileToUpload {
                background-color: #F9CC2C;
            }
            #info {
                background-color: #7EA2D6;
            }
        </style>
        <script>
            function validateFileSize(input) {
                const maxFileSize = <?php echo json_encode($maxFileSizeBytes); ?>;
                const file = input.files[0];
                if (file.size > maxFileSize) {
                    alert('File size exceeds the maximum limit of ' + <?php echo json_encode(ini_get("upload_max_filesize")); ?>);
                    input.value = ''; 
                    return false;
                }

                return true;
            }
        </script>
    </head>
    <body class="bg-gray-100 py-10">
    <div class="max-w-lg mx-auto bg-white p-6 rounded shadow-md">
        <h1 class="text-2xl font-semibold mb-4">Image Uploader</h1>
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST") handleFileUpload($maxFileSizeBytes); ?>
        <form action="" method="post" enctype="multipart/form-data" onsubmit="return validateFileSize(document.getElementById('fileToUpload'));">
            <div class="mb-4">
                <label for="fileToUpload" id="info" class="mt-1 block w-full border border-gray-300 rounded py-2 px-3">Maximum upload size is <?php echo htmlspecialchars($uploadMaxFilesize); ?> Contact DevOps to increase this value </label>
                <label for="fileToUpload" class="block text-gray-700">Select image to upload:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" class="mt-1 block w-full border border-gray-300 rounded py-2 px-3">
            </div>
            <button type="submit" name="submit" class="w-full bg-blue-custom text-white py-2 rounded">Upload Image</button>
        </form>
    </div>
    </body>
    </html>
    <?php
}

function handleFileUpload($maxFileSizeBytes) {
    $uploadDir = "uploads/";
    $uploadFile = $uploadDir . basename($_FILES["fileToUpload"]["name"]);
    $uploadOk = 1;
    $imageFileType = strtolower(pathinfo($uploadFile, PATHINFO_EXTENSION));

    $protocol = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off") || $_SERVER["SERVER_PORT"] == 443 ? "https://" : "http://";
    $hostName = $_SERVER["HTTP_HOST"];
    $path = dirname($_SERVER["SCRIPT_NAME"]);
    $baseUrl = $protocol . $hostName . $path;
    $base = rtrim($baseUrl, "/");


    if (!isset($_FILES["fileToUpload"]) || $_FILES["fileToUpload"]["error"] !== UPLOAD_ERR_OK) {
        echo "<p class='text-red-600'>You must upload a file</p>";
die();
    }
    

    if ($_FILES["fileToUpload"]["size"] > $maxFileSizeBytes) {
        echo "<p class='text-red-600'>Sorry, your file is too large. Maximum file size allowed is " . ini_get("upload_max_filesize") . ". <a href='mailto:devops@ivao.aero'>Contact DevOps</a> to increase this value.</p>";
        $uploadOk = 0;
    }

    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if ($check !== false) {
        echo "<p class='text-green-600'>File is an image - " . $check["mime"] . ".</p>";
        $uploadOk = 1;
    } else {
        echo "<p class='text-red-600'>File is not an image.</p>";
        $uploadOk = 0;
    }

    if (file_exists($uploadFile)) {
        echo "<p class='text-red-600'>Sorry, file already exists. You can access the existing file at: \n <a href='$uploadFile' class='text-blue-custom'>$base/$uploadFile</a></p>";
        $uploadOk = 0;
    }

    if ($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg" && $imageFileType != "gif") {
        echo "<p class='text-red-600'>Sorry, only JPG, JPEG, PNG & GIF files are allowed.</p>";
        $uploadOk = 0;
    }

    if ($uploadOk == 0) {
        echo "<b><p class='text-red-600'>Your file was not uploaded.</p></b>";
    } else {
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $uploadFile)) {
            echo "<p class='text-green-600'>The file " . htmlspecialchars(basename($_FILES["fileToUpload"]["name"])) . " has been uploaded. You can access the file at: \n <a href='$uploadFile' class='text-blue-custom'>$base/$uploadFile</a></p>";
        } else {
            echo "<p class='text-red-600'>Sorry, there was an error uploading your file.</p>";
        }
    }
}

function initiateOAuth2() {
    global $openid_data, $client_id, $redirect_uri;

    $state = bin2hex(random_bytes(16));
    $_SESSION["oauth2state"] = $state;

    $auth_url = $openid_data["authorization_endpoint"] .
        "?response_type=code&client_id=" .
        $client_id .
        "&redirect_uri=" .
        urlencode($redirect_uri) .
        "&scope=profile configuration email&state=" .
        $state;

    header("Location: " . $auth_url);
}
?>
