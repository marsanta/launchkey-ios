//
//  NSData+AES256.m
//  LaunchKey
//
//  Created by Kristin Tomasik on 2/2/13.
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import "NSData+LKAES256.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>

@implementation NSData (LKAES256)

NSData* iv;

- (NSData *)LKAES256EncryptWithKey:(NSString *)key
{
	// 'key' should be 32 bytes for AES256, will be null-padded otherwise
	char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
	bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
	
	// fetch key data
	BOOL result = [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	
    if (!result)
        return NULL;
    
	NSUInteger dataLength = [self length];
	
	//See the doc: For block ciphers, the output size will always be less than or
	//equal to the input size plus the size of one block.
	//That's why we need to add the size of one block here
	size_t bufferSize = dataLength + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);
    if (buffer == NULL)
    {
        return NULL;
    }
	
    NSString *test = [key substringToIndex:16];
    
    char ivPtr[16+1]; // room for terminator (unused)
	bzero(ivPtr, sizeof(ivPtr));
    
    // fetch key data
    result = [test getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    if (!result)
    {
        if(buffer) CFRelease(buffer);
        return NULL;
    }
    
	size_t numBytesEncrypted = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          0x0000, 
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          ivPtr,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
	if (cryptStatus == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
	}
    
	free(buffer); //free the buffer;
    buffer = NULL;
	return nil;
}


- (NSData *)LKAES256DecryptWithKey:(NSString *)key
{
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    BOOL result = [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    if (!result)
        return NULL;
    
    
    NSUInteger dataLength = [self length];
    
    //NSData* iv = [self randomDataOfLength:kCCBlockSizeAES128];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    if (buffer == NULL)
    {
        return NULL;
    }
    
    NSString *test = [key substringToIndex:16];
    
    char ivPtr[16+1]; // room for terminator (unused)
    bzero(ivPtr, sizeof(ivPtr));
    
    // fetch key data
    result = [test getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    if (!result)
    {
        if(buffer) CFRelease(buffer);
        return NULL;
    }
    
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          ivPtr,// iv.bytes, //NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer); //free the buffer;
    buffer = NULL;
    return nil;
}


- (NSData *)LKAES256DecryptWithKey:(NSString *)key withSalt:(NSString*)salt
{
    

	// 'key' should be 32 bytes for AES256, will be null-padded otherwise
	char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
	bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
	
	// fetch key data
	BOOL result = [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	
    if (!result)
        return NULL;
    
    
	NSUInteger dataLength = [self length];
    
    //NSData* iv = [self randomDataOfLength:kCCBlockSizeAES128];
	
	//See the doc: For block ciphers, the output size will always be less than or
	//equal to the input size plus the size of one block.
	//That's why we need to add the size of one block here
	size_t bufferSize = dataLength + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);
    
    if (buffer == NULL)
    {
        return NULL;
    }
    
    char ivPtr[16+1]; // room for terminator (unused)
    bzero(ivPtr, sizeof(ivPtr));
    
    // fetch key data
    result = [salt getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    if (!result)
    {
        if(buffer) CFRelease(buffer);
        return NULL;
    }
    
	size_t numBytesDecrypted = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          ivPtr,// iv.bytes, //NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
	
	if (cryptStatus == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
	}
	
	free(buffer); //free the buffer;
    buffer = NULL;
	return nil;
}

//32 bytes
- (NSData *)randomDataOfLength:(size_t)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault,
                                    length,
                                    data.mutableBytes);
    NSAssert(result == 0, @"Unable to generate random bytes: %d",
             errno);
    
    if (result)
        NSLog(@"an error occurred");
    
    return data;
}

@end