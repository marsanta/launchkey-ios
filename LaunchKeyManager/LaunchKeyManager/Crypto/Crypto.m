//
//  LKAuthenticationManager.h
//
//  Created by LaunchKey
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#import "NSData+Base64.h"
#import "Crypto.h"

@interface Crypto ()


@end

static NSString *x509PublicHeader = @"-----BEGIN PUBLIC KEY-----";
static NSString *x509PublicFooter = @"-----END PUBLIC KEY-----";
static NSString *pKCS1PublicHeader = @"-----BEGIN RSA PUBLIC KEY-----";
static NSString *pKCS1PublicFooter = @"-----END RSA PUBLIC KEY-----";
static NSString *pemPrivateHeader = @"-----BEGIN RSA PRIVATE KEY-----";
static NSString *pemPrivateFooter = @"-----END RSA PRIVATE KEY-----";

@implementation Crypto


#pragma mark - Encryption/Decryption Methods:

+(NSString *)decryptRSA:(NSString *)cipherString key:(NSString *)key
{
    size_t plainBufferSize;;
    uint8_t *plainBuffer;
    
    SecKeyRef privateKey = NULL;
    
    NSData *privateTag = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKey);
     
    if (!privateKey)
    {
        if(privateKey) CFRelease(privateKey);
        privateKey = NULL;
        return NULL;
    }
    
    plainBufferSize = SecKeyGetBlockSize(privateKey);
    plainBuffer = malloc(plainBufferSize);
    
    if (plainBuffer == NULL)
        return NULL;
    
    NSData *incomingData = [NSData dataFromBase64String:cipherString];
    uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);

    if (plainBufferSize < cipherBufferSize)
    {
        if(privateKey) CFRelease(privateKey);
        privateKey = NULL;
        return NULL;
    }
    
    SecKeyDecrypt(privateKey,
                  kSecPaddingOAEP,
                  cipherBuffer,
                  cipherBufferSize,
                  plainBuffer,
                  &plainBufferSize);
    
    NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    
    if(privateKey) CFRelease(privateKey);
    privateKey = NULL;
    
    return decryptedString;
}


+(NSString *)encryptRSA:(NSString *)plainTextString key:(NSString *)key
{
    NSData *publicTag = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef publicKey = NULL;

    
    SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKey);
    
    if (!publicKey)
    {
        if(publicKey) CFRelease(publicKey);
        
        return NULL;
    }
    
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    if (cipherBuffer == NULL)
        return NULL;

    uint8_t *nonce = (uint8_t *)[plainTextString UTF8String];

    if (cipherBufferSize < sizeof(nonce))
    {
        if(publicKey) CFRelease(publicKey);
        publicKey = NULL;
        return NULL;
    }
    
    SecKeyEncrypt(publicKey,
                  kSecPaddingOAEP,
                  nonce,
                  strlen( (char*)nonce ),
                  &cipherBuffer[0],
                  &cipherBufferSize);
    
    NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];

    if(publicKey) CFRelease(publicKey);
    publicKey = NULL;
    
    return [encryptedData base64EncodedString];
}

#pragma mark - Public/Private Key Import Methods:
+(void)setPrivateKey:(NSString *)pemPrivateKeyString tag:(NSString *)tag
{
    NSData *privateTag = [tag dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *privateKey = [[NSMutableDictionary alloc] init];
    [privateKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    NSString *strippedKey = nil;
    if (([pemPrivateKeyString rangeOfString:pemPrivateHeader].location != NSNotFound) && ([pemPrivateKeyString rangeOfString:pemPrivateFooter].location != NSNotFound))
    {
        strippedKey = [[pemPrivateKeyString stringByReplacingOccurrencesOfString:pemPrivateHeader withString:@""] stringByReplacingOccurrencesOfString:pemPrivateFooter withString:@""];
        strippedKey = [[strippedKey stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@" " withString:@""];
    }
    else
    {
        NSLog(@"Could not set private key.");
    }
    
    NSData *strippedPrivateKeyData = [NSData dataFromBase64String:strippedKey];
    
    CFTypeRef persistKey = nil;
    [privateKey setObject:strippedPrivateKeyData forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:(__bridge id)kSecAttrAccessibleWhenUnlocked forKey:(__bridge id)kSecAttrAccessible];
    
    OSStatus secStatus = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistKey);
    
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
    {
        NSLog(@"Could not set private key.");
    }
    
    SecKeyRef keyRef = nil;
    [privateKey removeObjectForKey:(__bridge id)kSecValueData];
    [privateKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    SecItemCopyMatching((__bridge CFDictionaryRef)privateKey,(CFTypeRef *)&keyRef);
    
    if (!keyRef)
    {
        NSLog(@"Could not set private key.");
    }
    
    if (keyRef) CFRelease(keyRef);
}


+(BOOL)setPublicKey:(NSString *)pemPublicKeyString tag:(NSString *)tag
{
    NSData *publicTag = [tag dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    BOOL isX509 = NO;
    
    NSString *strippedKey = nil;
    if (([pemPublicKeyString rangeOfString:x509PublicHeader].location != NSNotFound) && ([pemPublicKeyString rangeOfString:x509PublicFooter].location != NSNotFound))
    {
        strippedKey = [[pemPublicKeyString stringByReplacingOccurrencesOfString:x509PublicHeader withString:@""] stringByReplacingOccurrencesOfString:x509PublicFooter withString:@""];
        strippedKey = [[strippedKey stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        isX509 = YES;
    }
    else if (([pemPublicKeyString rangeOfString:pKCS1PublicHeader].location != NSNotFound) && ([pemPublicKeyString rangeOfString:pKCS1PublicFooter].location != NSNotFound))
    {
        strippedKey = [[pemPublicKeyString stringByReplacingOccurrencesOfString:pKCS1PublicHeader withString:@""] stringByReplacingOccurrencesOfString:pKCS1PublicFooter withString:@""];
        strippedKey = [[strippedKey stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        isX509 = NO;
    }
    else
    {
        return NO;
        
        strippedKey = pemPublicKeyString;
        isX509 = NO;
    }
    
    NSData *strippedPublicKeyData = [NSData dataFromBase64String:strippedKey];
    
    if (isX509)
    {
        unsigned char * bytes = (unsigned char *)[strippedPublicKeyData bytes];
        size_t bytesLen = [strippedPublicKeyData length];
        
        size_t i = 0;
        if (bytes[i++] != 0x30)
        {
            return NO;
        }
        
        /* Skip size bytes */
        if (bytes[i] > 0x80)
            i += bytes[i] - 0x80 + 1;
        else
            i++;
        
        if (i >= bytesLen)
        {
            return NO;
        }
        
        if (bytes[i] != 0x30)
        {
            return NO;
        }
        
        /* Skip OID */
        i += 15;
        
        if (i >= bytesLen - 2)
        {
            return NO;
        }
        
        if (bytes[i++] != 0x03)
        {
            return NO;
        }
        
        /* Skip length and null */
        if (bytes[i] > 0x80)
            i += bytes[i] - 0x80 + 1;
        else
            i++;
        
        if (i >= bytesLen)
        {
            return NO;
        }
        
        if (bytes[i++] != 0x00)
        {
            return NO;
        }
        
        if (i >= bytesLen)
        {
            return NO;
        }
        
        strippedPublicKeyData = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
    }
    

    if (strippedPublicKeyData == nil)
    {
        return NO;
    }
    
    CFTypeRef persistKey = nil;
    [publicKey setObject:strippedPublicKeyData forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus secStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
    {
        return NO;
    }
    
    SecKeyRef keyRef = nil;
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    SecItemCopyMatching((__bridge CFDictionaryRef)publicKey,(CFTypeRef *)&keyRef);
    
    if (!keyRef)
    {
        return NO;
    }
    
    if (keyRef) CFRelease(keyRef);
    
    return YES;
}

+ (NSData *)getSignatureBytes:(NSData *)plainText
{
	OSStatus sanityCheck = noErr;
	NSData * signedHash = nil;
	
	uint8_t * signedHashBytes = NULL;
	size_t signedHashBytesSize = 0;
	
    NSString *privateKeyStr = [NSString stringWithFormat:@"%@",  privateKeyString];
	NSData *privateTag = [privateKeyStr dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef privateKey = NULL;
    
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKey);
    
    if (err != noErr)
    {
        return NULL;
    }
    
	signedHashBytesSize = SecKeyGetBlockSize(privateKey);
	
	signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
	memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
	
	sanityCheck = SecKeyRawSign(privateKey,
                                kSecPaddingPKCS1SHA256,
                                (const uint8_t *)[[self getHash256Bytes:plainText] bytes],
                                CC_SHA256_DIGEST_LENGTH,
                                (uint8_t *)signedHashBytes,
                                &signedHashBytesSize
								);
	
	signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];
	
	if (signedHashBytes) free(signedHashBytes);
	
	return signedHash;
}

+ (NSData *)getHash256Bytes:(NSData *)plainText {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    if ( CC_SHA256([plainText bytes], [plainText length], hash) ) {
        NSData *sha256 = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
        return sha256;
    }
    return nil;
}

+(NSString*) get16BytePaddedJsonStringFromDictionary:(NSMutableDictionary*)dictionary {
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
                                                       options:0
                                                         error:&error];
    
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    
    int padding = (16 - [jsonData length] % 16);
    
    NSString *pad = [[NSString string] stringByPaddingToLength:padding withString:@" " startingAtIndex:0];
    NSString *appendedJson = [jsonString stringByAppendingString:pad];
    
    return appendedJson;
}

+(void)generateKeyPairWithPublicTag:(NSString *)publicTagString privateTag:(NSString *)privateTagString
{
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    NSData *publicTag = [publicTagString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *privateTag = [privateTagString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *privateKeyDictionary = [[NSMutableDictionary alloc] init];
    [privateKeyDictionary setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKeyDictionary setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKeyDictionary setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKeyDictionary);
    
    NSMutableDictionary *publicKeyDictionary = [[NSMutableDictionary alloc] init];
    [publicKeyDictionary setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyDictionary setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKeyDictionary setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKeyDictionary);
    
    
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA
                    forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithInt:1024]
                    forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    OSStatus err = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
    
    if (err != noErr)
    {
        //NSLog(@"Could not generate key pair.");
    }
    
    if(publicKey) CFRelease(publicKey);
    if(privateKey) CFRelease(privateKey);
}

+ (BOOL)verifySignature:(NSData *)plainText signature:(NSData *)sig
{
    NSString *pubKeyStr = [NSString stringWithFormat:@"%@", publicKeyString];
    NSData *publicTag = [pubKeyStr dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef publicKey = NULL;
    OSStatus err3 = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKey);
    
    if (err3 != noErr)
    {
        return NO;
    }
    
    size_t signedHashBytesSize = 0;
	OSStatus sanityCheck = noErr;
	
	// Get the size of the assymetric block.
	signedHashBytesSize = SecKeyGetBlockSize(publicKey);
	
	sanityCheck = SecKeyRawVerify(publicKey,
                                  kSecPaddingPKCS1SHA256,
                                  (const uint8_t *)[[self getHash256Bytes:plainText] bytes],
                                  CC_SHA256_DIGEST_LENGTH,
                                  (const uint8_t *)[sig bytes],
                                  signedHashBytesSize
								  );
	
	return (sanityCheck == noErr) ? YES : NO;
}

@end