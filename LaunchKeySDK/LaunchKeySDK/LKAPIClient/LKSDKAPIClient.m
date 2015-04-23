//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "LKSDKAPIClient.h"
#import "LKSDKJSONRequestOperation.h"
#import "LKSDKCrypto.h"
#import "NSData+LKBase64.h"

@implementation LKSDKAPIClient

#define kLKAPIClientBaseURLString @"https://api.launchkey.com/v1/"

+(LKSDKAPIClient *)sharedClient{
    
    static LKSDKAPIClient *_sharedClient = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedClient = [[LKSDKAPIClient alloc] initWithBaseURL:[NSURL URLWithString:kLKAPIClientBaseURLString]];
        [_sharedClient setParameterEncoding:AFJSONParameterEncoding];
    });
    
    return _sharedClient;
}

- (id)initWithBaseURL:(NSURL *)url {
    self = [super initWithBaseURL:url];
    if (!self) {
        return nil;
    }
    
    [self registerHTTPOperationClass:[LKSDKJSONRequestOperation class]];
	[self setDefaultHeader:@"Accept" value:@"application/json"];
    
    return self;
}

@end
