//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "LKAuthenticationManager.h"
#import "NSData+Base64.h"
#import "LKAPIClient.h"
#import "Crypto.h"

@implementation LKAuthenticationManager {
    NSTimer *_pollTimer;
    
    NSString *_privateKeyString;
    NSString *_secretKey;
    NSString *_appKey;
    NSString *_authRequest;
    NSString *_launchKeyTime;
    NSString *_userName;
    NSString *_userHash;
    NSString *_appPins;
    NSString *_deviceId;
    BOOL _session;
}

@synthesize thisSuccess, thisLogoutSuccess;
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

- (void)init:(NSString *)appKey withSecretKey:(NSString*)secretKey withPrivateKey:(NSString*)privateKey {
    //save the private key so we can use it for later
    [Crypto setPrivateKey:privateKey tag:privateKeyString];
    
    _secretKey = secretKey;
    _appKey = appKey;
    _session = true;
}

- (void)authorize:(NSString*)username isTransactional:(BOOL)transactional withSuccess:(successBlock)success withFailure:(failureBlock)failure {
    _session = !transactional;
    [self authorize:username withSuccess:success withFailure:failure];
}

- (void)authorize:(NSString*)username withSuccess:(successBlock)success withFailure:(failureBlock)failure {
    thisSuccess = success;
    thisFailure = failure;
    
    //call ping to get the server public key and time
    [[LKAPIClient sharedClient] getPath:@"ping" parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
        
        NSString *apiPublicKey = [responseObject objectForKey:@"key"];
        _launchKeyTime = [responseObject objectForKey:@"launchkey_time"];
        _userName = username;
        
        //save the public key so we can use it for later
        [Crypto setPublicKey:apiPublicKey tag:publicKeyString];
        
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
        
        //Do the POST
        [[LKAPIClient sharedClient] postPath:@"auths" parameters:postParams success:^(AFHTTPRequestOperation *operation, id responseObject) {
            
            _authRequest = [responseObject objectForKey:@"auth_request"];
            
            //build the url string to call the lauhcnkey app
            NSURL *launchKeyURL = [NSURL URLWithString:[NSString stringWithFormat:@"LK%d://appKey/%@/authRequest/%@/username/%@", LKAppId, _appKey, _authRequest, [username lowercaseString]]];
            BOOL canOpen = [[UIApplication sharedApplication] canOpenURL:launchKeyURL];
            
            //if the launchkey app is installed
            if (canOpen) {
                //open it
                [[UIApplication sharedApplication] openURL:launchKeyURL];
            } 
            
            //and start polling
            [self startPolling];
                        
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
        }];
        
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
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
    
    [[LKAPIClient sharedClient] getPath:@"poll" parameters:postParams success:^(AFHTTPRequestOperation *operation, id responseObject) {
        //stop the timer
        [self stopTimer];
        //cancel the previous timeout request
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(stopWaitingAndTimeout:) object:NULL];
        
        NSString *encryptedAuth = [responseObject objectForKey:@"auth"];
        _userHash = [responseObject objectForKey:@"user_hash"];
        
        //decrypt the server response
        NSString *decryptedResponse = [Crypto decryptRSA:encryptedAuth key:privateKeyString];
        
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
        _appPins = [jsonResponse objectForKey:@"app_pins"];
        _deviceId = [jsonResponse objectForKey:@"device_id"];
        _authRequest = [jsonResponse objectForKey:@"auth_request"];
        
        //tell the server what action was taken
        [self logsPut:action withAction:LKAuthenticate];
        
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        if (_session && [[self getErrorCode:error] isEqualToString:@"70404"]) {
            [self authenticationNotAuthorized:_userHash withAuthRequest:_authRequest withAppPins:_appPins withDeviceId:_deviceId];
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
    [[LKAPIClient sharedClient] getPath:@"ping" parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
        
        NSString *apiPublicKey = [responseObject objectForKey:@"key"];
        _launchKeyTime = [responseObject objectForKey:@"launchkey_time"];
        
        [Crypto setPublicKey:apiPublicKey tag:publicKeyString];
        
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
        
        [[LKAPIClient sharedClient] getPath:@"poll" parameters:postParams success:^(AFHTTPRequestOperation *operation, id responseObject) {
            //tell the user that the session is still active
            if (!_session) {
                [self authenticationFailure:@"Cannot check status of transactional log" withErrorCode:@"1000"];
            } else {
                [self stillAuthenticated:YES];
            }
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            //if the request has expired
            if ([[self getErrorCode:error] isEqualToString:@"70404"]){
                [self logsPut:YES withAction:LKRevoke];
                [self stillAuthenticated:NO];
            } else {
                [self stillAuthenticated:YES];
            }
        }];
        
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
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
    [[LKAPIClient sharedClient] getPath:@"ping" parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
        
        NSString *apiPublicKey = [responseObject objectForKey:@"key"];
        _launchKeyTime = [responseObject objectForKey:@"launchkey_time"];
        
        [Crypto setPublicKey:apiPublicKey tag:publicKeyString];
        
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
        
        [[LKAPIClient sharedClient] putPath:@"logs" parameters:postParams success:^(AFHTTPRequestOperation *operation, id responseObject) {
            //response appropriately
            if (status) {
                if ([action isEqualToString:LKAuthenticate]) {
                    [self authenticationAuthorized:_userHash withAuthRequest:_authRequest withAppPins:_appPins withDeviceId:_deviceId];
                } else if ([action isEqualToString:LKRevoke]) {
                    [self logoutSuccessful];
                }
            } else {
                if ([action isEqualToString:LKAuthenticate]) {
                    [self authenticationNotAuthorized:_userHash withAuthRequest:_authRequest withAppPins:_appPins withDeviceId:_deviceId];
                } else if ([action isEqualToString:LKRevoke]) {
                    [self logoutSuccessful];
                }
            }
            
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
        }];
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        [self authenticationFailure:[self getMessageCode:error] withErrorCode:[self getErrorCode:error]];
    }];
}

-(void)stillAuthenticated:(BOOL)status {
    if (thisPollSuccess != NULL) {
        thisPollSuccess(status);
    }
}

-(void)authenticationNotAuthorized:(NSString *)userHash withAuthRequest:(NSString*)authRequest withAppPins:(NSString*)appPins withDeviceId:(NSString*)deviceId {
    if (thisFailure != NULL) {
        thisFailure(@"1000", @"User denied request");
        thisFailure = NULL;
    }
}

-(void)authenticationAuthorized:(NSString *)userHash withAuthRequest:(NSString*)authRequest withAppPins:(NSString*)appPins withDeviceId:(NSString*)deviceId {
    if (thisSuccess != NULL) {
        thisSuccess(userHash, authRequest, appPins, deviceId);
        thisSuccess = NULL;
    }
}

-(void)logoutSuccessful  {
    if (thisLogoutSuccess != NULL) {
        thisLogoutSuccess();
    }
}

-(void)authenticationFailure:(NSString*)errorMessage withErrorCode:(NSString*)errorCode {
    [self stopTimer];
    if (thisFailure != NULL) {
        thisFailure(errorMessage, errorCode);
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
    NSString *appendedJson = [Crypto get16BytePaddedJsonStringFromDictionary:secretParams];
    NSString *encryptedSecret = [Crypto encryptRSA:appendedJson key:publicKeyString];
    
    return encryptedSecret;
}

- (NSString*)getSignatureOnSecretKey:(NSString*)secretKey {
    //get the signature bytes on the encryptes data
    NSData *signedData = [Crypto getSignatureBytes:[NSData dataFromBase64String:secretKey]];
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
