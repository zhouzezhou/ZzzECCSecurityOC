//
//  ViewController.m
//  ZzzECCSecurity
//
//  Created by 周泽舟 on 2021/3/29.
//  Copyright © 2021 zhouzezhou. All rights reserved.
//

#import "ViewController.h"
#import "ZzzECCSecurity.h"


static NSString *const kKeyIdentifier = @"123ZZZ";
// 签名原串
static NSString *const kOriStr = @"我是原串1234,，？abcd";

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    
    // 开发调试
//    [self devDebug];
    
    // 模拟运行
    [self simulateRun];
    
}

- (void)simulateRun {
    NSLog(@"");
    NSLog(@"======= START SIMULATE RUN =======");
        
    // 生成的密钥对，返回了公钥
    NSData *keyPublicCreate = [ZzzECCSecurity generateECCKeyPairWithIdentifier:kKeyIdentifier];
    NSLog(@"[create] public key is :%@", keyPublicCreate);

    // 查询公钥
    NSData *keyPublicQuery = [ZzzECCSecurity queryPublicKeyWithIdentifier:kKeyIdentifier];
    NSLog(@"[query] public key is :%@", keyPublicQuery);
    
    // 加签（签名）
    NSData *sourceData = [kOriStr dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signedData = [ZzzECCSecurity signPrivateKeyWithSource:sourceData identifier:kKeyIdentifier];
    NSLog(@"[sign] signed data is :%@", signedData);
    
    // 测试
    // 查询公钥
    SecKeyRef queryPublicKey = [ZzzECCSecurity queryPublicKeySecKeyRefWithIdentifier:kKeyIdentifier];
    // 验证签名
    BOOL b = [ZzzECCSecurity veriryWithSource:sourceData sign:signedData publicKey:queryPublicKey];
    NSLog(@"b is :%@", b ? @"YES" : @"NO");
    
    
    
    NSLog(@"======= END SIMULATE RUN =======");
    NSLog(@"");
}


- (void)devDebug {
    NSLog(@"");
    NSLog(@"======= START DEV DEBUG =======");
    
    
    //    [ZzzECCSecurity deleteAllKeyChain];
    //    [ZzzECCSecurity deleteECCKeyPairIdentifier:kKeyIdentifier];
    
    // 生成的密钥对，直接使用
    NSArray *keys = [ZzzECCSecurity generateECCKeyPairSecKeyRefWithIdentifier:kKeyIdentifier];
    if (!keys) return ;
    
    SecKeyRef privateKey = (__bridge SecKeyRef)keys.firstObject;
    SecKeyRef publicKey = (__bridge SecKeyRef)keys.lastObject;
    NSLog(@"[create] public key: %@", publicKey);
    NSLog(@"[create] privateKey key: %@", privateKey);
    NSLog(@"\n");
    NSLog(@"\n");
    
    
    // 查询公钥
    SecKeyRef queryPublicKey = [ZzzECCSecurity queryPublicKeySecKeyRefWithIdentifier:kKeyIdentifier];
    NSLog(@"[query] public key is :%@", queryPublicKey);
    
    // 查询私钥
    SecKeyRef queryPrivateKey = [ZzzECCSecurity queryPrivateKeySecKeyRefWithIdentifier:kKeyIdentifier];
    NSLog(@"[query] private key is :%@", queryPrivateKey);
    
    // 加签（签名）
    NSData *sourceData = [kOriStr dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signedData = [ZzzECCSecurity signWithSource:sourceData privateKey:queryPrivateKey];
    NSLog(@"[sign] signed data is :%@", signedData);
    
    // 验证签名
    BOOL b = [ZzzECCSecurity veriryWithSource:sourceData sign:signedData publicKey:queryPublicKey];
    NSLog(@"b is :%@", b ? @"YES" : @"NO");
    
    
    NSLog(@"======= END DEV DEBUG =======");
    NSLog(@"");
}


@end
