//
//  Test.m
//  Test
//
//  Created by Kristin Tomasik on 7/25/13.
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "Test.h"
#import "LKAuthenticationManager.h"
#import "Crypto.h"

@implementation Test

- (void)setUp
{
    [super setUp];
    
    STAssertNotNil([LKAuthenticationManager sharedClient], @"Could not create LKAuthenticationManager.");
    
    [Crypto generateKeyPairWithPublicTag:publicKeyString privateTag:privateKeyString];
}

- (void)tearDown
{
    
    [super tearDown];
}

- (void)verifyRSAEncryption {
    
    NSString *encryptedResult = [Crypto encryptRSA:@"test" key:publicKeyString];
    
    STAssertNotNil(encryptedResult, @"Problem encrypting string.");
    
    NSString *decryptedString = [Crypto decryptRSA:encryptedResult key:privateKeyString];
    
    STAssertNotNil(decryptedString, @"Problem decrypting string.");
}

- (void)verifyKeySigning {
    NSData *signature = [Crypto getSignatureBytes:[encryptedResult dataUsingEncoding:NSUTF8StringEncoding]];
    
    STAssertNotNil(encryptedResult, @"Problem signing.");
    
    BOOL verified = [Crypto verifySignature:[encryptedResult dataUsingEncoding:NSUTF8StringEncoding] signature:signature];
    
    STAssertTrue(verified, @"Problem verifying signature.");
    
}

@end
