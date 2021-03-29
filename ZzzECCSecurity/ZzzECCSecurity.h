//
//  ZzzECCSecurity.h
//
//  Created by 周泽舟 on 2021/3/29.
//  Copyright © 2021 zhouzezhou. All rights reserved.
//  ECC椭圆加密算法(Elliptic curve cryptography)（公私钥对）相关方法类（生成、查询、签名等）

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZzzECCSecurity : NSObject

//MARK:- 对外开放的方法

/// 生成ECC公私钥对
///
/// @discussion 1. 本方法会默认将公私钥对存入KeyChain
/// @discussion 2. 私钥的访问控制（kSecAttrAccessControl）设置为系统默认值
/// @param identifier 此公私钥对的唯一标识
/// @return 返回公钥的NSData对象
/// @date 2021-03-29 16:13:28
/// @author zhouzezhou
+ (NSData *)generateECCKeyPairWithIdentifier:(NSString *)identifier;

/// 查询ECC公钥
/// @param identifier 唯一标识，用于查找对应的公钥，此值应与生成时相同
/// @return ECC公钥的NSData对象
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (NSData *)queryPublicKeyWithIdentifier:(NSString *)identifier;

/// 使用私钥对数据进行签名
/// @param source 需要签名的数据NSData对象
/// @param identifier 唯一标识，用于查找对应的私钥，此值应与生成时相同
/// @return 使用私钥签名后的数据
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (NSData *)signPrivateKeyWithSource:(NSData *)source identifier:(NSString *)identifier;


//MARK:- 开发过种中调试需要用到的方法，在打包时请禁用

/// 删除当前App下所有的KeyChain数据，慎用！慎用！慎用！
///
/// @discussion 建议仅在开发、调试过程中使用
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (void)deleteAllKeyChain;

/// 删除指定ECC公私钥对
/// @param identifier 此公私钥对的唯一标识
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (void)deleteECCKeyPairIdentifier:(NSString *)identifier;

/// 生成ECC公私钥对
/// @param identifier 此公私钥对的唯一标识
/// @return 返回公私钥的SecKeyRef对象数组，数组第1项为公钥，第2项为私钥
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (NSArray *)generateECCKeyPairSecKeyRefWithIdentifier:(NSString *)identifier;

/// 查询ECC公钥
/// @param identifier 唯一标识，用于查找对应的公钥，此值应与生成时相同
/// @return ECC公钥的SecKeyRef对象
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (SecKeyRef)queryPublicKeySecKeyRefWithIdentifier:(NSString *)identifier;

/// 查询ECC私钥
/// @param identifier 唯一标识，用于查找对应的私钥，此值应与生成时相同
/// @return ECC私钥的SecKeyRef对象
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (SecKeyRef)queryPrivateKeySecKeyRefWithIdentifier:(NSString *)identifier;

/// 使用私钥对数据进行签名
/// @param source 需要签名的数据NSData对象
/// @param privateKey 私钥的SecKeyRef对象
/// @return 使用私钥签名后的数据
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (NSData *)signWithSource:(NSData *)source privateKey:(SecKeyRef)privateKey;

/// 使用私钥对数据进行验签
/// @param source 签名前的数据的NSData对象
/// @param sign 已签名的数据的NSData对象
/// @param publicKey 私钥的SecKeyRef对象
/// @return 是否通过验签，YES验签通过，NO验签不通过
/// @date 2021-03-29 16:27:46
/// @author zhouzezhou
+ (BOOL)veriryWithSource:(NSData *)source sign:(NSData *)sign publicKey:(SecKeyRef)publicKey;

@end

NS_ASSUME_NONNULL_END
