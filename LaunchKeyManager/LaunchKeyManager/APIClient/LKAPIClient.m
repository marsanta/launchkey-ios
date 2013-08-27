//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "LKAPIClient.h"
#import "AFJSONRequestOperation.h"
#import "Crypto.h"
#import "NSData+Base64.h"

@implementation LKAPIClient

#define kLKAPIClientBaseURLString @"https://api.launchkey.com/v1/"

+(LKAPIClient *)sharedClient{
    
    static LKAPIClient *_sharedClient = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedClient = [[LKAPIClient alloc] initWithBaseURL:[NSURL URLWithString:kLKAPIClientBaseURLString]];
        [_sharedClient setParameterEncoding:AFFormURLParameterEncoding];
    });
    
    return _sharedClient;
}

- (id)initWithBaseURL:(NSURL *)url {
    self = [super initWithBaseURL:url];
    if (!self) {
        return nil;
    }
    
    [self registerHTTPOperationClass:[AFJSONRequestOperation class]];
	[self setDefaultHeader:@"Accept" value:@"application/json"];
    
    return self;
}

@end
