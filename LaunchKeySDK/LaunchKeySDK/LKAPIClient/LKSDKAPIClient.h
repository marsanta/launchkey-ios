//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "LKSDKHTTPClient.h"

@interface LKSDKAPIClient : LKSDKHTTPClient

+ (LKSDKAPIClient *)sharedClient;

@end
