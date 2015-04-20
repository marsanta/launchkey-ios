# LaunchKey iOS SDK

  * [Overview](#overview)
  * [Pre-Requisites](#prerequisites)
  * [Obtaining the Framework](#obtaining)
    * [Dependency Management](#dependency-management)
    * [Manual Installation](#manual-installation)
  * [Usage](#usage)
  * [Support](#support)

# <a name="overview"></a>Overview

LaunchKey is an identity and access management platform  This iOS SDK enables developers to quickly integrate
the LaunchKey platform and iOS based applications without the need to directly interact with the platform API.

Developer documentation for using the LaunchKey API is found [here](https://launchkey.com/docs/).

An overview of the LaunchKey platform can be found [here](https://launchkey.com/platform).

#  <a name="prerequisites"></a>Pre-Requisites

Utilization of the LaunchKey SDK requires the following items:

 * LaunchKey Account - The [LaunchKey Mobile App](https://launchkey.com/app) is required to set up a new account and
 access the LaunchKey Dashboard.
 
 * An application - A new application can be created in the [LaunchKey Dashboard](https://dashboard.launchkey.com/).
   From the application, you will need the following items found in the keys section of the application details:

    * The app key
    * The secret key
    * The private key

#  <a name="obtaining"></a>Obtaining the Framework

The framework, source, and doc files are available through either CocoaPods or GitHub.

## <a name="dependency-management"></a>CocoaPods (Suggested)

_CocoaPods Example:_

```
$ sudo gem install launchkey-sdk
```

## <a name="manual-installation"></a>Manual Installation (Not Suggested)

Download the framework for the LaunchKey SDK and add them to your project:

  * [LaunchKey SDK](https://s3.amazonaws.com/launchkey-sdk/ios/LaunchKeyManager.framework.zip)

__Due to the number of dependencies required by the LaunchKey SDK, it would be best to use a dependency management tool__

#  <a name="usage"></a>Usage

  1. Initialize the LKAuthenticationManager

    ```objective-c
    [[LKAuthenticationManager sharedClient] init:@"Your App Key"
                                   withSecretKey:@"Your Secret Key"
                                  withPrivateKey:@"Your Private Key"];
    ```

  2. Use the SDK
    * Authorize a user identifier via LaunchKey. The identifier can either be the LaunchKey username, userPushId or unique identifier (used in the whitelabel pairing process)

        ```objective-c
        [[LKAuthenticationManager sharedClient] authorize:@"identifier" withSuccess:^(NSString *userHash, NSString *authRequest, NSString *userPushId, NSString *deviceId) {
    
		} withFailure:^(NSString *errorMessage, NSString *errorCode) {
     		//error handling
		}];
        ```

    * Determine whether the username is still authorized (i.e. has not remotely ended the session)

        ```objective-c
        [[LKAuthenticationManager sharedClient] isAuthorized:@"authRequest" withSuccess:^(BOOL authorized) {
        
    	} withFailure:^(NSString *errorMessage, NSString *errorCode) {
        	//error handling
    	}];
        ```

    * End a session

        ```objective-c
        [[LKAuthenticationManager sharedClient] logout:@"authRequest" withSuccess:^{
        
    	} withFailure:^(NSString *errorMessage, NSString *errorCode) {
        	//error handling
    	}];
        ```
        
    * Add a white label user

        ```objective-c

        [[LKAuthenticationManager sharedClient] createWhiteLabelUser:@"identifier"withSuccess:^(NSString *qrCode, NSString *qrUrl) {
        	// Show the user the QR Code from the QR Code URL to be validated in a white label application
    	} withFailure:^(NSString *errorMessage, NSString *errorCode) {
        	//error handling
    	}];

        ```

#  <a name="support"></a>Support

## GitHub

Submit feature requests and bugs on [GitHub](https://github.com/LaunchKey/launchkey-ios/issues).

## Twitter

Submit a question to the Twitter Handle [@LaunchKeyHelp](https://twitter.com/LaunchKeyHelp).

## IRC

Engage the LaunchKey team in the `#launchkey` chat room on [freenode](https://freenode.net/).

## LaunchKey Help Desk

Browse FAQ's or submit a question to the LaunchKey support team for both
technical and non-technical issues. Visit the LaunchKey Help Desk [here](https://launchkey.desk.com/).