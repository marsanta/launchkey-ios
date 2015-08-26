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
typedef void (^lkSuccessBlock)(NSString *userHash, NSString *authRequest, NSString* userPushId, NSString *deviceId);
typedef void (^whiteLabelSuccessBlock)(NSString *authRequest);
typedef void (^lkFailureBlock)(NSString *errorMessage, NSString *errorCode);
typedef void (^lkRegisterSuccessBlock)(NSString *qrCode, NSString *qrUrl);

@interface LKAuthenticationManager : NSObject

@property (nonatomic, copy) lkSuccessBlock thisSuccess;
@property (nonatomic, copy) lkFailureBlock thisFailure;
@property (nonatomic, copy) pollSuccessBlock thisPollSuccess;
@property (nonatomic, copy) logoutSuccessBlock thisLogoutSuccess;
@property (nonatomic, copy) lkRegisterSuccessBlock thisRegisterSuccess;
@property (nonatomic, copy) whiteLabelSuccessBlock thisWhiteLabelSuccess;


+ (LKAuthenticationManager *)sharedClient;

- (void)initWithKeys:(NSString *)rocketKey withSecretKey:(NSString*)secretKey withPrivateKey:(NSString*)privateKey;
- (void)initAsWhiteLabel:(NSString *)rocketKey withSecretKey:(NSString*)secretKey withPrivateKey:(NSString*)privateKey;

- (void)authorize:(NSString*)username withSuccess:(lkSuccessBlock)success withFailure:(lkFailureBlock)failure;
- (void)authorize:(NSString*)username isTransactional:(BOOL)transactional withUserPushId:(BOOL)pushId withSuccess:(lkSuccessBlock)success withFailure:(lkFailureBlock)failure;

- (void)logout:(NSString*)authRequest withSuccess:(logoutSuccessBlock)success withFailure:(lkFailureBlock)failure;
- (void)isAuthorized:(NSString*)authRequest withSuccess:(pollSuccessBlock)success withFailure:(lkFailureBlock)failure;

- (BOOL)handleOpenUrl:(NSURL *)url;

- (void)createWhiteLabelUser:(NSString*)identifier withSuccess:(lkRegisterSuccessBlock)success withFailure:(lkFailureBlock)failure;

@end
