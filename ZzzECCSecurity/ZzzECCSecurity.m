//
//  ZzzECCSecurity.m
//
//
//  Created by 周泽舟 on 2021/3/29.
//  Copyright © 2021 zhouzezhou. All rights reserved.
//

#import "ZzzECCSecurity.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation ZzzECCSecurity

+ (NSData *)generateECCKeyPairWithIdentifier:(NSString *)identifier {
    [self generateECCKeyPairSecKeyRefWithIdentifier:identifier];
    NSData *data = [self queryPublicKeyWithIdentifier:identifier];
    return data;
}

+ (NSArray *)generateECCKeyPairSecKeyRefWithIdentifier:(NSString *)identifier {
    if (@available(iOS 9.0, *)) {
        // 使用SecKeyGeneratePair()方法生成公私钥对时，公私钥对会自动存入KeyChain
        // 所以在生成新的公私钥对前，总是先删除现有的，否则新的公私钥对将无法保存成功（且无法得知）
        // 2021-03-29 15:00:46 zhouzezhou
        [self deleteECCKeyPairIdentifier:identifier];
        
        // 私钥的属性
        NSMutableDictionary *privateKeyAttrs = [NSMutableDictionary dictionary];
        // 是否永久保存加密密钥
        privateKeyAttrs[(__bridge id)kSecAttrIsPermanent] = @YES;
        // 标签
        privateKeyAttrs[(__bridge id)kSecAttrLabel] = identifier;
        // 标签(私有标签数据)，设置了kSecAttrLabel的话此值也可以不设置
        privateKeyAttrs[(__bridge id)kSecAttrApplicationTag] = identifier;
        
        
        // 公钥的属性
        NSMutableDictionary *publicKeyAttrs = [NSMutableDictionary dictionary];
        // 是否永久保存加密密钥
        // kSecAttrIsPermanent default false，if this key is present
        // and has a Boolean value of true, the key or key pair will be added to the keychain.
        publicKeyAttrs[(__bridge id)kSecAttrIsPermanent] = @YES;
        // 标签
        publicKeyAttrs[(__bridge id)kSecAttrLabel] = identifier;
        // 标签(私有标签数据)
        publicKeyAttrs[(__bridge id)kSecAttrApplicationTag] = identifier;
        
        
        // 参数字典
        NSMutableDictionary *params = [NSMutableDictionary dictionary];
        // 令牌
        params[(__bridge id)kSecAttrTokenID] = (__bridge id)kSecAttrTokenIDSecureEnclave;
        // 加密密钥类型(算法)
        params[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeEC;
        // 密钥总位数
        params[(__bridge id)kSecAttrKeySizeInBits] = @256;
        params[(__bridge id)kSecPrivateKeyAttrs] = privateKeyAttrs;
        params[(__bridge id)kSecPublicKeyAttrs] = publicKeyAttrs;
        
        
        
        SecKeyRef publicKey = NULL;
        SecKeyRef privateKey = NULL;
        // 生成密钥对
        // SecKeyGeneratePair()方法在模拟器上运行会报EXC_BAD_ACCESS的错误 2021-03-29 15:09:24 zhouzezhou
        OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)params, &publicKey, &privateKey);
        
        if (errSecSuccess == status) {
            return @[(__bridge id)privateKey, (__bridge id)publicKey];
        }
    }
    
    return nil;
}

+ (NSData *)queryPublicKeyWithIdentifier:(NSString *)identifier {
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPublicKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
    [queryPublicKey setObject:(id)kSecAttrKeyClassPublic forKey:(id)kSecAttrKeyClass];
    [queryPublicKey setObject:identifier forKey:(id)kSecAttrLabel];
    [queryPublicKey setObject:@YES forKey:(id)kSecReturnData];
    
    SecKeyRef result = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)queryPublicKey, (CFTypeRef *)&result);
    
    NSData *dataKey = nil;
    if (errSecSuccess == status) {
        dataKey = CFBridgingRelease(result);
        
        return dataKey;
    }
    
    return dataKey;
}

+ (SecKeyRef)queryPublicKeySecKeyRefWithIdentifier:(NSString *)identifier {
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPublicKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
    [queryPublicKey setObject:(id)kSecAttrKeyClassPublic forKey:(id)kSecAttrKeyClass];
    [queryPublicKey setObject:identifier forKey:(id)kSecAttrLabel];
    [queryPublicKey setObject:@YES forKey:(id)kSecReturnRef];
    
    SecKeyRef result = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)queryPublicKey, (CFTypeRef *)&result);
    
    if (errSecSuccess == status) {
        return result;
    }
    
    return result;
}


+ (SecKeyRef)queryPrivateKeySecKeyRefWithIdentifier:(NSString *)identifier {
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPrivateKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
    [queryPrivateKey setObject:(id)kSecAttrKeyClassPrivate forKey:(id)kSecAttrKeyClass];
    [queryPrivateKey setObject:identifier forKey:(id)kSecAttrLabel];
    [queryPrivateKey setObject:@YES forKey:(id)kSecReturnRef];
    
    SecKeyRef result = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&result);
    
    if (errSecSuccess == status) {
        return result;
    }
    
    return result;
}

+ (void)deleteECCKeyPairIdentifier:(NSString *)identifier {
    if (!identifier || identifier.length == 0) return ;
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    //    query[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeEC;
    //    query[(__bridge id)kSecAttrApplicationTag] = identifier;
    query[(__bridge id)kSecAttrLabel] = identifier;
    
    SecItemDelete((__bridge CFDictionaryRef)query);
    
//    OSStatus statusDel = SecItemDelete((__bridge CFDictionaryRef)query);
//    NSLog(@"status delete is :%d", (int)statusDel);
}

+ (void)deleteAllKeyChain {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
                                  (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
                                  nil];
    NSArray *secItemClasses = [NSArray arrayWithObjects:
                               (__bridge id)kSecClassGenericPassword,
                               (__bridge id)kSecClassInternetPassword,
                               (__bridge id)kSecClassCertificate,
                               (__bridge id)kSecClassKey,
                               (__bridge id)kSecClassIdentity,
                               nil];
    for (id secItemClass in secItemClasses) {
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];
        
        CFTypeRef result = NULL;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        
//        OSStatus statusQuery = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
//        NSLog(@"status Query is :%d", (int)statusQuery);
        
        if (result != NULL) CFRelease(result);
        
        NSDictionary *spec = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)spec);
        
//        OSStatus statusDel = SecItemDelete((__bridge CFDictionaryRef)spec);
//        NSLog(@"status delete is :%d", (int)statusDel);
    }
}


//MARK:- 加签验签

+ (NSData *)signPrivateKeyWithSource:(NSData *)source identifier:(NSString *)identifier {
    SecKeyRef privateKey = [self queryPrivateKeySecKeyRefWithIdentifier:identifier];
    NSData *signStr = [self signWithSource:source privateKey:privateKey];
    return signStr;
}

+ (NSData *)signWithSource:(NSData *)source privateKey:(SecKeyRef)privateKey {
    NSData *sign = nil;
    
    if (source && privateKey) {
        // 待签名数据摘要
        NSMutableData *digestToSign = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(source.bytes, (CC_LONG) source.length, digestToSign.mutableBytes);
        
        // 签名后数据
        uint8_t signature[128];
        size_t signatureLength = sizeof(signature);
        
        // 执行签名
        OSStatus status = SecKeyRawSign(privateKey,
                                        kSecPaddingPKCS1SHA1,
                                        digestToSign.bytes,
                                        CC_SHA1_DIGEST_LENGTH,
                                        (uint8_t *)signature,
                                        &signatureLength);
        
        // 签名结果数据格式转化
        NSData *signedData = [NSData dataWithBytes:(const void *)signature length:signatureLength];
        
        // 结果处理
        if (errSecSuccess == status) {
            sign = signedData;
        }
    }
    
    return sign;
}

+ (BOOL)veriryWithSource:(NSData *)source sign:(NSData *)sign publicKey:(SecKeyRef)publicKey {
    BOOL success = NO;
    
    if (source && sign && publicKey) {
        // 待签名数据摘要
        NSMutableData *digestToSign = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(source.bytes, (CC_LONG) source.length, digestToSign.mutableBytes);
        
        // 执行验签
        OSStatus status = SecKeyRawVerify(publicKey,
                                          kSecPaddingPKCS1SHA1,
                                          (uint8_t *)digestToSign.bytes,
                                          CC_SHA1_DIGEST_LENGTH,
                                          (uint8_t *)sign.bytes,
                                          sign.length);
        
        // 结果处理
        if (errSecSuccess == status) {
            success = YES;
        }
    }
    
    return success;
}

@end
