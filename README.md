# esp32_adapter_driver
- Raspberry Pi에서 동작하는 ESP32 Wi-Fi 어댑터 디바이스 드라이버
## 개발환경
- H/W : 라즈베리파이4, esp32 devkit v1 
- OS : Raspberry Pi OS, Kernel 5.1
- Program Language : C
- Tools : WireShark, VScode, MobaXterm
  
## S/W 구조
![image](https://github.com/smtobs/esp32_adapter/assets/50127167/42ce9ebb-83e3-4495-997b-a3e1706e58a4)


## 기능 구현 목록
- iw 명령어를 통하여 사용자 영역과 Wi-Fi 드라이버와 통신을 하기 위하여 cfg80211 등록
- iw dev scan 기능을 수행 하기 위하여 Wi-Fi의 관리 프레임을 생성 및 파싱 (probe request 생성, probe response 파싱)
- ping 명령어의 ICMP Request와 Reply 패킷을 송 수신하기 위하여 네트워크 디바이스 등록을 통하여 네트워크 인터페이스 생성
- 네트워크 디바이스에게 전달 된 패킷의 이더넷 헤더를 분해하여 Wi-Fi 데이터 프레임을 생성 후 SPI 인터페이스로 송신
- SPI 인터페이스로 수신 된 Wi-Fi 데이터 패킷을 이더넷 프레임으로 변경 후 네트워크 디바이스에게 전달
- 사용자 영역에서 Wi-Fi Driver를 제어를 위한 vendor commands를 적용하여 커스텀 명령어 적용. (Wi-Fi 연결을 해제 하기 위한 deauthentication 프레임 생성)
- Wi-Fi 모듈에서 Wi-Fi 프레임을 전송하기 위한 ESP32 모듈 Firmware 개발 (https://github.com/smtobs/esp32_module.git)

## 참조


