# 개요

Spring Security 기능 중 SecurityContext를 사용하면 User 정보를 Controller 레이어에서 매개변수로 사용가능하다. 이때 User를 조회하는 기능을 Redis-in-memory 로 구현했을 때와 MariaDB 데이터베이스로 구현했을 때 성능 및 속도차이를 비교한다.

### 테스트 환경

- Windows 11 Home
- CPU : Ryzen 5600X
- RAM : DDR4 32GB
- SSD: SK-Hynix Platinum P41
- MariaDB : 11.4.7-MariaDB (windows)
- Redis :  8.0.2-alpine(docker desktop으로 로컬에서 image 사용)

Java VM Option

```java
-Xms4096m -Xmx4096m -Dreactor.schedulers.defaultBoundedElasticSize=12
```

## 성능 측정

Jmeter 설정

- 요청 쓰레드 : 10개
- Ramp-up period : 2초
- Loop Count : Infinity
- Duration : 180s
- Startup delay : 3s

SecurityContext에 저장된 `principal` 에서 사용자 이름을 return하는 API 를 위 설정으로 무한 요청

```java
@GetMapping("/me")
    @PreAuthorize("hasAnyAuthority('USER_ROLE', 'ADMIN_ROLE')")
    public Mono<ResponseEntity<String>> getCurrentUser(Mono<Principal> principal) {
        return principal
                .map(Principal::getName)
                .map(name -> ResponseEntity.ok("Hello, " + name + "! You are authenticated."))
                .defaultIfEmpty(ResponseEntity.status(401).body("Unauthorized"));
    }
```

## Redis

### 기록

| Label | # Samples | Average | Min | Max | Std. Dev. | Error % | Throughput | Received KB/sec | Sent KB/sec | Avg. Bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| /users/me | 527,240 | 3 | 1 | 1011 | 20.77 | 0.00% | 2929.11111 | 906.77 | 1161.35 | 317 |
| TOTAL | 527,240 | 3 | 1 | 1011 | 20.77 | 0.00% | 2929.11111 | 906.77 | 1161.35 | 317 |

### CPU

### Heap

## MariaDB

### 기록

| Label | # Samples | Average | Min | Max | Std. Dev. | Error % | Throughput | Received KB/sec | Sent KB/sec | Avg. Bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| /users/me | 133,853 | 13 | 0 | 5042 | 246.41 | 0.24% | 734.24575 | 231.47 | 290.41 | 322.8 |
| TOTAL | 133,853 | 13 | 0 | 5042 | 246.41 | 0.24% | 734.24575 | 231.47 | 290.41 | 322.8 |

### CPU

### Heap

## 결론

Redis가 4배 정도 응답 처리속도(Throughput)가 빠르며 표준 편차(Std. Dev -Standard Deviation) 역시 낮다.

MariaDB는 SSD에서 값을 조회하므로 병목 현상이 CPU와 SSD간의 병목 때문에 응답처리에 지연이 발생한다. 반면 Redis는 인메모리에서 조회하므로 응답속도가 빠르다. 그리고 그에 따른 CPU및 Heap 자원을 짧은 시간안에 더 잘 활용하므로 그림에서 CPU 및 Memory 사용량이 높은 것으로 판단된다.

Redis에서 Max HeapSize를 8Gb로 늘리면 더 성능 향상이 있을 지 확인하는 것도 좋을 듯 하다.