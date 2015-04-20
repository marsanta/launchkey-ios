//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "LKHTTPClient.h"

@interface LKAPIClient : LKHTTPClient

+ (LKAPIClient *)sharedClient;

@end
