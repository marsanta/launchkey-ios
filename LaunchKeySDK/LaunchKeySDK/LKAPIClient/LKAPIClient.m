//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "LKAPIClient.h"
#import "LKJSONRequestOperation.h"
#import "LKCrypto.h"
#import "NSData+LKBase64.h"

@implementation LKAPIClient

#define kLKAPIClientBaseURLString @"https://staging-api.launchkey.com/v1/"

+(LKAPIClient *)sharedClient{
    
    static LKAPIClient *_sharedClient = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedClient = [[LKAPIClient alloc] initWithBaseURL:[NSURL URLWithString:kLKAPIClientBaseURLString]];
        [_sharedClient setParameterEncoding:AFJSONParameterEncoding];
    });
    
    return _sharedClient;
}

- (id)initWithBaseURL:(NSURL *)url {
    self = [super initWithBaseURL:url];
    if (!self) {
        return nil;
    }
    
    [self registerHTTPOperationClass:[LKJSONRequestOperation class]];
	[self setDefaultHeader:@"Accept" value:@"application/json"];
    
    return self;
}

@end
