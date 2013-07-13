//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class LKAuthenticationManager;

typedef void (^pollSuccessBlock)(BOOL authorized);
typedef void (^logoutSuccessBlock)();
typedef void (^successBlock)(NSString *userHash, NSString *authRequest, NSString *pins, NSString *deviceId);
typedef void (^failureBlock)(NSString *errorMessage, NSString *errorCode);

@interface LKAuthenticationManager : NSObject

@property (nonatomic, copy) successBlock thisSuccess;
@property (nonatomic, copy) failureBlock thisFailure;
@property (nonatomic, copy) logoutSuccessBlock thisLogoutSuccess;
@property (nonatomic, copy) pollSuccessBlock thisPollSuccess;

+ (LKAuthenticationManager *)sharedClient;
- (void)init:(NSString *)appKey withSecretKey:(NSString*)secretKey withPrivateKey:(NSString*)privateKey;
- (void)authorize:(NSString*)username withSuccess:(successBlock)success withFailure:(failureBlock)failure;
- (void)authorize:(NSString*)username isTransactional:(BOOL)transactional withSuccess:(successBlock)success withFailure:(failureBlock)failure;
- (void)logout:(NSString*)authRequest withSuccess:(logoutSuccessBlock)success withFailure:(failureBlock)failure;
- (void)isAuthorized:(NSString*)authRequest withSuccess:(pollSuccessBlock)success withFailure:(failureBlock)failure;
- (BOOL)handleOpenUrl:(NSURL *)url;

@end
