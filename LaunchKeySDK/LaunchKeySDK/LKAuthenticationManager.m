//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "LKAuthenticationManager.h"
#import "NSData+LKBase64.h"
#import "LKAPIClient.h"
#import "LKCrypto.h"
#import "NSData+LKAES256.h"

@implementation LKAuthenticationManager {
    NSTimer *_pollTimer;
    
    NSString *_privateKeyString;
    NSString *_secretKey;
    NSString *_appKey;
    NSString *_authRequest;
    NSString *_launchKeyTime;
    NSString *_userName;
    NSString *_userHash;
    NSString *_deviceId;
    NSString *_userPushId;
    BOOL _session;
    BOOL _hasUserPushId;
    BOOL _isWhiteLabel;
}

@synthesize thisSuccess, thisLogoutSuccess, thisRegisterSuccess;
@synthesize thisFailure, thisPollSuccess;

#define LKPollingTimer 3
#define LKTimeout 60
#define LKAppId 1000000000
#define LKAuthenticate @"Authenticate"
#define LKRevoke @"Revoke"


+(LKAuthenticationManager *)sharedClient{
    static LKAuthenticationManager *_sharedClient = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedClient = [[LKAuthenticationManager alloc] init];
    });
    
    return _sharedClient;
}

- (void)initAsWhiteLabel:(NSString *)appKey withSecretKey:(NSString*)secretKey withPrivateKey:(NSString*)privateKey {
   
    [self init:appKey withSecretKey:secretKey withPrivateKey:privateKey];
     _isWhiteLabel = true;
}

- (void)init:(NSString *)appKey withSecretKey:(NSString*)secretKey withPrivateKey:(NSString*)privateKey {
    //save the private key so we can use it for later
    [LKCrypto setPrivateKey:privateKey tag:privateKeyString];
    
    _secretKey = secretKey;
    _appKey = appKey;
    _session = true;
    _hasUserPushId = false;
     _isWhiteLabel = false;
}

- (void)createWhiteLabelUser:(NSString*)identifier withSuccess:(registerSuccessBlock)success withFailure:(failureBlock)failure {
    thisRegisterSuccess = success;
    thisFailure = failure;
    
    identifier = [identifier lowercaseString];
    
    //call ping to get the server public key and time
    [[LKAPIClient sharedClient] getPath:@"ping" parameters:nil success:^(LKHTTPRequestOperation *operation, id responseObject) {
        
        NSString *apiPublicKey = [responseObject objectForKey:@"key"];
        _launchKeyTime = [responseObject objectForKey:@"launchkey_time"];
        
        //save the public key so we can use it for later
        [LKCrypto setPublicKey:apiPublicKey tag:publicKeyString];
        
        //encrypt the secret key
        NSString *encryptedSecret = [self getEncryptedSecretKey];
        
                
        //build the parameters for auths POST
        NSMutableDictionary *postParams = [NSMutableDictionary dictionary];
        
        [postParams setObject:encryptedSecret forKey:@"secret_key"];
        [postParams setObject:identifier forKey:@"identifier"];
        [postParams setObject:_appKey forKey:@"app_key"];
        
        NSData *policyData = [NSJSONSerialization dataWithJSONObject:postParams options:kNilOptions error:nil];

        //remove the extra escapes
        NSString *policyStr = [[NSString alloc] initWithData:policyData encoding:NSUTF8StringEncoding];
        policyStr = [policyStr stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];
        policyData = [policyStr dataUsingEncoding:NSUTF8StringEncoding];
        
        
        //sign the encrypted package
        NSString *signedDataString = [self getSignatureOnBodyWithoutDecoding:policyData];

        //strip the new lines
        signedDataString = [signedDataString stringByReplacingOccurrencesOfString:@"\r\n" withString:@""];

        //url encode the signature
        NSString *encodedString = (NSString *)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(NULL, (CFStringRef)signedDataString, NULL, (CFStringRef)@"!*'();:@&=+$,/?%#[]", kCFStringEncodingUTF8));
        
        NSString *postPath = [NSString stringWithFormat:@"users?signature=%@", encodedString];
        
        //Do the POST
        [[LKAPIClient sharedClient] JSONpostPath:postPath parameters:policyData success:^(LKHTTPRequestOperation *operation, id responseObject) {
            
            @try {
                //get the cipher and the data
                NSString *cipher = [[responseObject objectForKey:@"response"] objectForKey:@"cipher"];
                NSString *dataString = [[responseObject objectForKey:@"response"] objectForKey:@"data"];
                
                //RSA decrypt with the Rocket private key
                NSString *decryptedCipher = [LKCrypto decryptRSA:cipher key:privateKeyString];
                
                //extract the token and salt
                NSString *token = [decryptedCipher substringToIndex:32];
                NSString *salt = [decryptedCipher substringWithRange:NSMakeRange(32, 16)];
                
                //base64 decode
                NSData *dataStringData = [NSData dataFromBase64String:dataString];
                
                //decrypt with token and salt
                NSData *decryptedData = [dataStringData LKAES256DecryptWithKey:token withSalt:salt];
                NSString *unencryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
                
                //convert to JSON dictionary
                NSMutableDictionary *dictionary = [NSJSONSerialization JSONObjectWithData: [unencryptedString dataUsingEncoding:NSUTF8StringEncoding]
                                                                                  options: NSJSONReadingMutableContainers
                                                                                    error: nil];
                
                thisRegisterSuccess([dictionary objectForKey:@"code"], [dictionary objectForKey:@"qrcode"]);
            } @catch (NSException *exception) {
                
            }
            
        } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
            [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
        }];
        
    } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
        [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
    }];
}

- (void)authorize:(NSString*)username isTransactional:(BOOL)transactional withSuccess:(successBlock)success withFailure:(failureBlock)failure {
    _session = !transactional;
    username = [username lowercaseString];
    _hasUserPushId = false;
    [self authorize:username withSuccess:success withFailure:failure];
}

- (void)authorize:(NSString*)username isTransactional:(BOOL)transactional withUserPushId:(BOOL)pushId withSuccess:(successBlock)success withFailure:(failureBlock)failure {
    _session = !transactional;
    _hasUserPushId = pushId;
    username = [username lowercaseString];
    [self authorize:username withSuccess:success withFailure:failure];
}

- (void)authorize:(NSString*)username withSuccess:(successBlock)success withFailure:(failureBlock)failure {
    thisSuccess = success;
    thisFailure = failure;
    
    //call ping to get the server public key and time
    [[LKAPIClient sharedClient] getPath:@"ping" parameters:nil success:^(LKHTTPRequestOperation *operation, id responseObject) {
        
        NSString *apiPublicKey = [responseObject objectForKey:@"key"];
        _launchKeyTime = [responseObject objectForKey:@"launchkey_time"];
        _userName = username;
        
        //save the public key so we can use it for later
        [LKCrypto setPublicKey:apiPublicKey tag:publicKeyString];
        
        //encrypt the secret key
        NSString *encryptedSecret = [self getEncryptedSecretKey];
        //sign the encrypted package
        NSString *signedDataString = [self getSignatureOnSecretKey:encryptedSecret];
        NSString *boolString = [NSString stringWithFormat:@"%s", _session ? "true" : "false"];
        
        //build the parameters for auths POST
        NSMutableDictionary *postParams = [NSMutableDictionary dictionary];
        
        [postParams setObject:_appKey forKey:@"app_key"];
        [postParams setObject:encryptedSecret forKey:@"secret_key"];
        [postParams setObject:signedDataString forKey:@"signature"];
        [postParams setObject:_userName forKey:@"username"];
        [postParams setObject:boolString forKey:@"session"];
        [postParams setObject:[NSString stringWithFormat:@"%s", _hasUserPushId ? "true" : "false"] forKey:@"user_push_id"];
        
        //Do the POST
        [[LKAPIClient sharedClient] postPath:@"auths" parameters:postParams success:^(LKHTTPRequestOperation *operation, id responseObject) {
            
            _authRequest = [responseObject objectForKey:@"auth_request"];
            
            if(!_isWhiteLabel) {
                //build the url string to call the lauhcnkey app
                NSURL *launchKeyURL = [NSURL URLWithString:[NSString stringWithFormat:@"LK%d://appKey/%@/authRequest/%@/username/%@", LKAppId, _appKey, _authRequest, [username lowercaseString]]];
                BOOL canOpen = [[UIApplication sharedApplication] canOpenURL:launchKeyURL];
                
                //if the launchkey app is installed
                if (canOpen) {
                    //open it
                    [[UIApplication sharedApplication] openURL:launchKeyURL];
                }
            }
            
            //and start polling
            [self startPolling];
            
        } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
            [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
        }];
        
    } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
        [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
    }];
}

- (void)pollRequest {
     //encrypt the secret key
    NSString *encryptedSecret = [self getEncryptedSecretKey];
    //sign the encrypted package
    NSString *signedDataString = [self getSignatureOnSecretKey:encryptedSecret];
    
    //build the params for the Poll GET
    NSMutableDictionary *postParams = [NSMutableDictionary dictionary];
    
    [postParams setObject:_appKey forKey:@"app_key"];
    [postParams setObject:encryptedSecret forKey:@"secret_key"];
    [postParams setObject:signedDataString forKey:@"signature"];
    [postParams setObject:_authRequest forKey:@"auth_request"];
    
    //Stop the last Poll if it is taking a long time
    [[LKAPIClient sharedClient] cancelAllHTTPOperationsWithMethod:@"GET" path:@"poll"];
    
    [[LKAPIClient sharedClient] getPath:@"poll" parameters:postParams success:^(LKHTTPRequestOperation *operation, id responseObject) {
        //stop the timer
        [self stopTimer];
        //cancel the previous timeout request
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(stopPollingAndTimeout:) object:NULL];
        
        NSString *encryptedAuth = [responseObject objectForKey:@"auth"];
        _userHash = [responseObject objectForKey:@"user_hash"];
        _userPushId = [responseObject objectForKey:@"user_push_id"];
        
        //decrypt the server response
        NSString *decryptedResponse = [LKCrypto decryptRSA:encryptedAuth key:privateKeyString];
        
        //convert response to json dictionary
        NSData *jsonData = [decryptedResponse dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *jsonResponse= [NSJSONSerialization JSONObjectWithData: jsonData
                                                            options: NSJSONReadingMutableContainers
                                                              error: nil];
        
        //if auth request is not the same, something bad happened
        if (![_authRequest isEqualToString:[jsonResponse objectForKey:@"auth_request"]]) {
            [self authenticationFailure:@"Auth tokens do not match" withErrorCode:@"70401"];
            return;
        }
        
        BOOL action = [[jsonResponse objectForKey:@"response"] boolValue];
        _deviceId = [jsonResponse objectForKey:@"device_id"];
        _authRequest = [jsonResponse objectForKey:@"auth_request"];
        
        //tell the server what action was taken
        [self logsPut:action withAction:LKAuthenticate];
        
    } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
        if (_session && [[self getErrorCode:error] isEqualToString:@"70404"]) {
            [self authenticationNotAuthorized:_userHash withAuthRequest:_authRequest withDeviceId:_deviceId];
        } else if (![[self getErrorCode:error] isEqualToString:@"70403"]) {
            [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
        }
    }];
}

- (void)isAuthorized:(NSString*)authRequest withSuccess:(pollSuccessBlock)success withFailure:(failureBlock)failure {
    thisPollSuccess = success;
    thisFailure = failure;
    _authRequest = authRequest;
    
    //get the launchkey public key and server time
    [[LKAPIClient sharedClient] getPath:@"ping" parameters:nil success:^(LKHTTPRequestOperation *operation, id responseObject) {
        
        NSString *apiPublicKey = [responseObject objectForKey:@"key"];
        _launchKeyTime = [responseObject objectForKey:@"launchkey_time"];
        
        [LKCrypto setPublicKey:apiPublicKey tag:publicKeyString];
        
        //encrypt the secret key
        NSString *encryptedSecret = [self getEncryptedSecretKey];
        //sign the encrypted package
        NSString *signedDataString = [self getSignatureOnSecretKey:encryptedSecret];
        
        //build the Poll GET parameters
        NSMutableDictionary *postParams = [NSMutableDictionary dictionary];
        
        [postParams setObject:_appKey forKey:@"app_key"];
        [postParams setObject:encryptedSecret forKey:@"secret_key"];
        [postParams setObject:signedDataString forKey:@"signature"];
        [postParams setObject:_authRequest forKey:@"auth_request"];
        
        [[LKAPIClient sharedClient] getPath:@"poll" parameters:postParams success:^(LKHTTPRequestOperation *operation, id responseObject) {
            //tell the user that the session is still active
            if (!_session) {
                [self authenticationFailure:@"Cannot check status of transactional log" withErrorCode:@"1000"];
            } else {
                [self stillAuthenticated:YES];
            }
        } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
            //if the request has expired
            if ([[self getErrorCode:error] isEqualToString:@"70404"]){
                [self logsPut:YES withAction:LKRevoke];
                [self stillAuthenticated:NO];
            } else {
                [self stillAuthenticated:YES];
            }
        }];
        
    } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
        [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
    }];
}

-(void)logout:(NSString*)authRequest withSuccess:(logoutSuccessBlock)success withFailure:(failureBlock)failure {
    thisLogoutSuccess = success;
    thisFailure = failure;
    _authRequest = authRequest;
    
    [self logsPut:YES withAction:LKRevoke];
}

-(void)logsPut:(BOOL)status withAction:(NSString*)action{
    //get the LaunchKey server time and public key
    [[LKAPIClient sharedClient] getPath:@"ping" parameters:nil success:^(LKHTTPRequestOperation *operation, id responseObject) {
        
        NSString *apiPublicKey = [responseObject objectForKey:@"key"];
        _launchKeyTime = [responseObject objectForKey:@"launchkey_time"];
        
        [LKCrypto setPublicKey:apiPublicKey tag:publicKeyString];
        
        //encrypt the secret key
        NSString *encryptedSecret = [self getEncryptedSecretKey];
        //sign the encrypted package
        NSString *signedDataString = [self getSignatureOnSecretKey:encryptedSecret];
        NSString *statusString = [NSString stringWithFormat:@"%s", status ? "true" : "false"];
        
        //build the Logs PUT parameters
        NSMutableDictionary *postParams = [NSMutableDictionary dictionary];
        
        [postParams setObject:_appKey forKey:@"app_key"];
        [postParams setObject:encryptedSecret forKey:@"secret_key"];
        [postParams setObject:signedDataString forKey:@"signature"];
        [postParams setObject:action forKey:@"action"];
        [postParams setObject:statusString forKey:@"status"];
        [postParams setObject:_authRequest forKey:@"auth_request"];
        
        [[LKAPIClient sharedClient] putPath:@"logs" parameters:postParams success:^(LKHTTPRequestOperation *operation, id responseObject) {
            //response appropriately
            if (status) {
                if ([action isEqualToString:LKAuthenticate]) {
                    [self authenticationAuthorized:_userHash withAuthRequest:_authRequest withUserPushId:_userPushId withDeviceId:_deviceId];
                } else if ([action isEqualToString:LKRevoke]) {
                    [self logoutSuccessful];
                }
            } else {
                if ([action isEqualToString:LKAuthenticate]) {
                    [self authenticationNotAuthorized:_userHash withAuthRequest:_authRequest withDeviceId:_deviceId];
                } else if ([action isEqualToString:LKRevoke]) {
                    [self logoutSuccessful];
                }
            }
            
        } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
            [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
        }];
    } failure:^(LKHTTPRequestOperation *operation, NSError *error) {
        [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
    }];
}

-(void)stillAuthenticated:(BOOL)status {
    if (thisPollSuccess != NULL) {
        thisPollSuccess(status);
        thisPollSuccess = NULL;
    }
}

-(void)authenticationNotAuthorized:(NSString *)userHash withAuthRequest:(NSString*)authRequest withDeviceId:(NSString*)deviceId {
    if (thisFailure != NULL) {
        thisFailure(@"1000", @"User denied request");
        thisFailure = NULL;
    }
}

-(void)authenticationAuthorized:(NSString *)userHash withAuthRequest:(NSString*)authRequest withUserPushId:(NSString*)pushId withDeviceId:(NSString*)deviceId {
    if (thisSuccess != NULL) {
        thisSuccess(userHash, authRequest, pushId, deviceId);
        thisSuccess = NULL;
    }
}

-(void)logoutSuccessful  {
    if (thisLogoutSuccess != NULL) {
        thisLogoutSuccess();
        thisLogoutSuccess = NULL;
    }
}

-(void)authenticationFailure:(NSString*)errorMessage withErrorCode:(NSString*)errorCode {
    [self stopTimer];
    if (thisFailure != NULL) {
        thisFailure(errorMessage, errorCode);
        thisFailure = NULL;
    }
}

-(BOOL)handleOpenUrl:(NSURL *)url {
    NSDictionary *userDict = [self urlPathToDictionary:url.absoluteString];
    
    if ([userDict objectForKey:@"error"] != NULL) {
        //there was an auth error when the user interacted with the LaunchKey app
        if ([[userDict objectForKey:@"error"] isEqualToString:@"authError"]) {
            [self authenticationFailure:@"User Authentication Error" withErrorCode:@"1000"];
        }
        return NO;
    } else {
        return YES;
    }
}

-(void)stopTimer {
    //stop the timer
    if (_pollTimer != NULL) {
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(stopPollingAndTimeout:) object:NULL];
        [_pollTimer invalidate];
        _pollTimer = NULL;
    }
}

- (void)startPolling {
    //start polling
    [self stopTimer];
    _pollTimer = [NSTimer scheduledTimerWithTimeInterval:LKPollingTimer
                                                  target:self
                                                selector:@selector(checkServer)
                                                userInfo:nil
                                                 repeats:YES];
    
    [self performSelector:@selector(stopPollingAndTimeout:)
               withObject:NO
               afterDelay:LKTimeout];
}

-(void)checkServer {
    //poll the server
    [self pollRequest];
}


- (void)stopPollingAndTimeout:(BOOL)authenticated {
    [self authenticationFailure:@"Response Timeout" withErrorCode:@"1000"];
}

- (NSString*)getEncryptedSecretKey {
    //create the secret_key dictionary
    NSMutableDictionary *secretParams = [NSMutableDictionary dictionary];
    
    [secretParams setObject:_secretKey forKey:@"secret"];
    [secretParams setObject:_launchKeyTime forKey:@"stamped"];
    
    //encrypt with the apis public key
    NSString *appendedJson = [LKCrypto get16BytePaddedJsonStringFromDictionary:secretParams];
    NSString *encryptedSecret = [LKCrypto encryptRSA:appendedJson key:publicKeyString];
    
    return encryptedSecret;
}

- (NSString*)getSignatureOnBodyWithoutDecoding:(NSData*)bodyData {
    //get the signature bytes on the encryptes data
    NSData *signedData = [LKCrypto getSignatureBytes:bodyData];
    //base64 encode them
    NSString *signedDataString = [signedData base64EncodedString];
    
    return signedDataString;
}

- (NSString*)getSignatureOnSecretKey:(NSString*)secretKey {
    //get the signature bytes on the encryptes data
    NSData *signedData = [LKCrypto getSignatureBytes:[NSData dataFromBase64String:secretKey]];
    //base64 encode them
    NSString *signedDataString = [signedData base64EncodedString];
    
    return signedDataString;
}

-(NSDictionary *)urlPathToDictionary:(NSString *)path
{
    //Get the string everything after the :// of the URL.
    NSString *stringNoPrefix = [[path componentsSeparatedByString:@"://"] lastObject];
    //Get all the parts of the url
    NSMutableArray *parts = [[stringNoPrefix componentsSeparatedByString:@"/"] mutableCopy];
    //Make sure the last object isn't empty
    if([[parts lastObject] isEqualToString:@""])[parts removeLastObject];
    
    if([parts count] % 2 != 0)//Make sure that the array has an even number
        return nil;
    
    //We already know how many values there are, so don't make a mutable dictionary larger than it needs to be.
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithCapacity:([parts count] / 2)];
    
    //Add all our parts to the dictionary
    for (int i=0; i<[parts count]; i+=2) {
        [dict setObject:[parts objectAtIndex:i+1] forKey:[parts objectAtIndex:i]];
    }
    
    //Return an NSDictionary, not an NSMutableDictionary
    return [NSDictionary dictionaryWithDictionary:dict];
}

-(NSString*)getMessageCode:(NSError *)error
{
    //parse the error message code
    @try {
        NSDictionary *JSON =
        [NSJSONSerialization JSONObjectWithData: [[[error userInfo] objectForKey:NSLocalizedRecoverySuggestionErrorKey] dataUsingEncoding:NSUTF8StringEncoding]
                                        options: NSJSONReadingMutableContainers
                                          error: nil];
        
        NSString *code = [JSON objectForKey:@"message"];
        return code;
    } @catch (NSException * e) {
        return @"";
    }
}

-(NSString*)getErrorCode:(NSError *)error
{
    //parse the error code
    @try {
        NSDictionary *JSON =
        [NSJSONSerialization JSONObjectWithData: [[[error userInfo] objectForKey:NSLocalizedRecoverySuggestionErrorKey] dataUsingEncoding:NSUTF8StringEncoding]
                                        options: NSJSONReadingMutableContainers
                                          error: nil];
        
        NSString *code = [[JSON objectForKey:@"message_code"] stringValue];
        return code;
    } @catch (NSException * e) {
        return @"";
    }
}


@end
