//
//  NSData+LKAES256.h
//  LaunchKey
//
//  Created by Kristin Tomasik on 2/2/13.
//  Copyright (c) 2013 LaunchKey, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (LKAES256)

-(NSData *)LKAES256EncryptWithKey:(NSString *)key;
-(NSData *)LKAES256DecryptWithKey:(NSString *)key;
-(NSData *)LKAES256DecryptWithKey:(NSString *)key withSalt:(NSString*)salt;

@end