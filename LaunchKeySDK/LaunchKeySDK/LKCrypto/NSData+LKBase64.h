//
//  NSData+LKBase64.h
//  LaunchKey
//
//  Created by Kristin Tomasik on 2/2/13.
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

void *LKBase64Decode(
                     const char *inputBuffer,
                     size_t length,
                     size_t *outputLength);

char *LKBase64Encode(
                     const void *inputBuffer,
                     size_t length,
                     bool separateLines,
                     size_t *outputLength);

@interface NSData (LKBase64)

+ (NSData *)dataFromBase64String:(NSString *)aString;
- (NSString *)base64EncodedString;

@end
