//go:build darwin && cgo

#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <string.h>
#import <Security/Security.h>
#import <Network/Network.h>
#import <TargetConditionals.h>
#if TARGET_OS_OSX
#import <CoreWLAN/CoreWLAN.h>
#endif
#import "http_client_apple.h"
extern void lanboatAppleHeaders(uintptr_t,int,char *,size_t);
extern int lanboatAppleData(uintptr_t,void *,size_t);
extern void lanboatAppleDone(uintptr_t,int);
extern int lanboatAppleTrust(uintptr_t,void *,size_t);

@interface LanboatAppleSession : NSObject <NSURLSessionDataDelegate,NSURLSessionTaskDelegate>
@property(nonatomic,strong) NSURLSession *session;
@property(nonatomic,copy) NSString *user;
@property(nonatomic,copy) NSString *password;
@property(nonatomic) int proxyPort;
@end
@implementation LanboatAppleSession
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completion {
 NSHTTPURLResponse *http=(NSHTTPURLResponse *)response;
 NSData *headers=[NSJSONSerialization dataWithJSONObject:http.allHeaderFields options:0 error:nil];
 lanboatAppleHeaders((uintptr_t)task.taskDescription.longLongValue,(int)http.statusCode,(char *)headers.bytes,headers.length);
 completion(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data {
 if(!lanboatAppleData((uintptr_t)task.taskDescription.longLongValue,(void *)data.bytes,data.length)){[task cancel];}
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
 lanboatAppleDone((uintptr_t)task.taskDescription.longLongValue,error?(int)error.code:0);
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest *))completion {
 completion(nil);
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition,NSURLCredential *))completion {
 NSString *method=challenge.protectionSpace.authenticationMethod;
 if(challenge.protectionSpace.isProxy && challenge.protectionSpace.port==self.proxyPort && ([challenge.protectionSpace.host isEqualToString:@"127.0.0.1"] || [challenge.protectionSpace.host isEqualToString:@"localhost"]) && [method isEqualToString:NSURLAuthenticationMethodHTTPBasic]) {
  completion(NSURLSessionAuthChallengeUseCredential,[NSURLCredential credentialWithUser:self.user password:self.password persistence:NSURLCredentialPersistenceForSession]);return;
 }
 if([method isEqualToString:NSURLAuthenticationMethodServerTrust]) {
  SecTrustRef trust=challenge.protectionSpace.serverTrust;
  SecTrustEvaluateWithError(trust,NULL);
  NSMutableData *chain=[NSMutableData data];
  CFIndex count=SecTrustGetCertificateCount(trust);
  for(CFIndex i=0;i<count;i++) {
   SecCertificateRef certificate=SecTrustGetCertificateAtIndex(trust,i);
   NSData *der=CFBridgingRelease(SecCertificateCopyData(certificate));
   uint32_t length=htonl((uint32_t)der.length);[chain appendBytes:&length length:4];[chain appendData:der];
  }
  if(lanboatAppleTrust((uintptr_t)task.taskDescription.longLongValue,(void *)chain.bytes,chain.length)) {
   completion(NSURLSessionAuthChallengeUseCredential,[NSURLCredential credentialForTrust:trust]);return;
  }
  completion(NSURLSessionAuthChallengeCancelAuthenticationChallenge,nil);return;
 }
 completion(NSURLSessionAuthChallengeRejectProtectionSpace,nil);
}
- (void)URLSession:(NSURLSession *)session didBecomeInvalidWithError:(NSError *)error {self.session=nil;}
@end

void *lanboat_apple_session(int port,const char *user,const char *password,int minimum,int maximum) {
 @autoreleasepool {
  LanboatAppleSession *delegate=[LanboatAppleSession new];
  delegate.proxyPort=port;delegate.user=[NSString stringWithUTF8String:user];delegate.password=[NSString stringWithUTF8String:password];
  NSURLSessionConfiguration *config=[NSURLSessionConfiguration ephemeralSessionConfiguration];
  config.URLCredentialStorage=nil;config.URLCache=nil;config.HTTPCookieStorage=nil;config.HTTPShouldSetCookies=NO;config.HTTPMaximumConnectionsPerHost=4;
  config.timeoutIntervalForRequest=30;config.timeoutIntervalForResource=300;
  config.connectionProxyDictionary=@{@"HTTPEnable":@YES,@"HTTPProxy":@"127.0.0.1",@"HTTPPort":@(port),@"HTTPSEnable":@YES,@"HTTPSProxy":@"127.0.0.1",@"HTTPSPort":@(port)};
  if(@available(macOS 10.15,iOS 13.0,*)){config.TLSMinimumSupportedProtocolVersion=minimum;config.TLSMaximumSupportedProtocolVersion=maximum;}
  NSOperationQueue *queue=[NSOperationQueue new];queue.maxConcurrentOperationCount=1;
  delegate.session=[NSURLSession sessionWithConfiguration:config delegate:delegate delegateQueue:queue];
  return (__bridge_retained void *)delegate;
 }
}
void lanboat_apple_start(void *pointer,uintptr_t handle,const char *url,const char *method,const char *headers,void *body,size_t length) {
 @autoreleasepool {
  LanboatAppleSession *delegate=(__bridge LanboatAppleSession *)pointer;
  NSURL *target=[NSURL URLWithString:[NSString stringWithUTF8String:url]];
  if(!target){dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{lanboatAppleDone(handle,-1000);});return;}
  NSMutableURLRequest *request=[NSMutableURLRequest requestWithURL:target];
  request.HTTPMethod=[NSString stringWithUTF8String:method];
  NSData *encoded=[[NSString stringWithUTF8String:headers] dataUsingEncoding:NSUTF8StringEncoding];
  request.allHTTPHeaderFields=[NSJSONSerialization JSONObjectWithData:encoded options:0 error:nil];
  if(length){request.HTTPBody=[NSData dataWithBytes:body length:length];}
  NSURLSessionDataTask *task=[delegate.session dataTaskWithRequest:request];task.taskDescription=[NSString stringWithFormat:@"%llu",(unsigned long long)handle];[task resume];
 }
}
void lanboat_apple_cancel(void *pointer,uintptr_t handle) {
 LanboatAppleSession *delegate=(__bridge LanboatAppleSession *)pointer;
 [delegate.session getAllTasksWithCompletionHandler:^(NSArray<NSURLSessionTask *> *tasks){for(NSURLSessionTask *task in tasks){if(task.taskDescription.longLongValue==handle){[task cancel];}}}];
}
void lanboat_apple_finish(void *pointer) {LanboatAppleSession *delegate=(__bridge LanboatAppleSession *)pointer;[delegate.session finishTasksAndInvalidate];CFRelease(pointer);}
void lanboat_apple_retain(void *pointer){CFRetain(pointer);}
void lanboat_apple_release(void *pointer){CFRelease(pointer);}

char *lanboat_apple_network(void) {
 @autoreleasepool {
  NSMutableDictionary *result=[NSMutableDictionary dictionary];
#if TARGET_OS_OSX
  CWInterface *wifi=[[CWWiFiClient sharedWiFiClient] interface];
  if(wifi.ssid){result[@"ssid"]=wifi.ssid;}if(wifi.bssid){result[@"bssid"]=wifi.bssid;}
#endif
  if(@available(macOS 10.15,iOS 13.0,*)){
   nw_path_monitor_t monitor=nw_path_monitor_create();
   dispatch_semaphore_t ready=dispatch_semaphore_create(0);
   nw_path_monitor_set_queue(monitor,dispatch_get_global_queue(QOS_CLASS_UTILITY,0));
   nw_path_monitor_set_update_handler(monitor,^(nw_path_t path){
    @synchronized(result){result[@"expensive"]=@(nw_path_is_expensive(path));result[@"constrained"]=@(nw_path_is_constrained(path));}
    dispatch_semaphore_signal(ready);
   });
   nw_path_monitor_start(monitor);dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC));nw_path_monitor_cancel(monitor);
   @synchronized(result){NSData *data=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];NSString *text=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];return strdup(text.UTF8String);}
  }
  NSData *data=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];NSString *text=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];return strdup(text.UTF8String);
 }
}
