<?php
/**
 * Example of retrieving the products list using Admin account via Magento REST API. OAuth authorization is used
 * Preconditions:
 * 1. Install php oauth extension
 * 2. If you were authorized as a Customer before this step, clear browser cookies for 'yourhost'
 * 3. Create at least one product in Magento
 * 4. Configure resource permissions for Admin REST user for retrieving all product data for Admin
 * 5. Create a Consumer
 */
// $callbackUrl is a path to your file with OAuth authentication example for the Admin user
$callbackUrl = "https://canddev-matthiasmedia.cs8.force.com/services/apexrest/magento/callback";
$temporaryCredentialsRequestUrl = "http://matthiasmedia.com/oauth/initiate?oauth_callback=" . urlencode($callbackUrl);
$adminAuthorizationUrl = 'http://matthiasmedia.com/admin/oAuth_authorize';
$accessTokenRequestUrl = 'http://matthiasmedia.com/oauth/token';
$apiUrl = 'http://matthiasmedia.com/api/rest';
$consumerKey = 'xh0hjtaiz3khtqf9tj1ascxi6dd5gndd';
$consumerSecret = 'yrQqO3mFzOOkOqrI459vXrqrmkQ';

session_start();
if (!isset($_GET['oauth_token']) && isset($_SESSION['state']) && $_SESSION['state'] == 1) {
    $_SESSION['state'] = 0;
}
try {
    $authType = ($_SESSION['state'] == 2) ? OAUTH_AUTH_TYPE_AUTHORIZATION : OAUTH_AUTH_TYPE_URI;
    $oauthClient = new OAuth($consumerKey, $consumerSecret, OAUTH_SIG_METHOD_HMACSHA1, $authType);
    $oauthClient->enableDebug();

    if (!isset($_GET['oauth_token']) && !$_SESSION['state']) {
        $requestToken = $oauthClient->getRequestToken($temporaryCredentialsRequestUrl);
        $_SESSION['secret'] = $requestToken['oauth_token_secret'];
        $_SESSION['state'] = 1;
        header('Location: ' . $adminAuthorizationUrl . '?oauth_token=' . $requestToken['oauth_token']);
        exit;
    } else if ($_SESSION['state'] == 1) {
        $oauthClient->setToken($_GET['oauth_token'], $_SESSION['secret']);
        $accessToken = $oauthClient->getAccessToken($accessTokenRequestUrl);
        $_SESSION['state'] = 2;
        $_SESSION['token'] = $accessToken['oauth_token'];
        $_SESSION['secret'] = $accessToken['oauth_token_secret'];
        header('Location: ' . $callbackUrl);
        exit;
    } else {
        $oauthClient->setToken($_SESSION['token'], $_SESSION['secret']);

        $resourceUrl = "$apiUrl/products";
        $oauthClient->fetch($resourceUrl, array(), 'GET', array('Content-Type' => 'application/json'));
        $productsList = json_decode($oauthClient->getLastResponse());
        print_r($productsList);
    }
} catch (OAuthException $e) {
    print_r($e->getMessage());
    echo "<br/>";
    print_r($e->lastResponse);
}