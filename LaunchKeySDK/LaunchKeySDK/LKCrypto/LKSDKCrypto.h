//
//  LKCrypto.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#define privateKeyString @"launchkeyPrivateKey"
#define publicKeyString @"launchkeyPublicKey"

@interface LKSDKCrypto : NSObject

+(NSString *)encryptRSA:(NSString *)plainTextString key:(NSString *)key;
+(NSString *)decryptRSA:(NSString *)cipherString key:(NSString *)key;

+(void)setPrivateKey:(NSString *)pemPrivateKeyString tag:(NSString *)tag;
+(BOOL)setPublicKey:(NSString *)pemPublicKeyString tag:(NSString *)tag;

+(NSData *)getSignatureBytes:(NSData *)plainText;
+(NSString*)get16BytePaddedJsonStringFromDictionary:(NSMutableDictionary*)dictionary;
+(void)generateKeyPairWithPublicTag:(NSString *)publicTagString privateTag:(NSString *)privateTagString;
+(BOOL)verifySignature:(NSData *)plainText signature:(NSData *)sig;

@end