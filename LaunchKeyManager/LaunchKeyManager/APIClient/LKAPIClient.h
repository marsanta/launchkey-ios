//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "AFHTTPClient.h"

@interface LKAPIClient : AFHTTPClient

+ (LKAPIClient *)sharedClient;

@end
