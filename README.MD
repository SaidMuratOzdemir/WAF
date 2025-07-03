# BOTAŞ WAF (Web Application Firewall)

Bu proje, BOTAŞ Siber Gğvenlik stajı kapsamında geliştirilmiş bir Web Application Firewall (WAF) uygulamasıdır. Bu WAF, kötü niyetli HTTP isteklerini tespit ederek engeller ve güvenli istekleri backend sunucuya yönlendirir.

## Proje Yapısı

Proje iki ana bileşenden oluşmaktadır:

1. **proxy_waf.py**: Ana WAF uygulaması. HTTP isteklerini alır, güvenlik kontrollerini yapar ve güvenli istekleri backend sunucuya iletir.
2. **mitmproxy_to_aiohttp.py**: mitmproxy için yazılmış ek bir güvenlik katmanı. Bu script, mitmproxy üzerinden geçen istekleri kontrol eder, analiz eder, istekleri gösterir.

## Nasıl Çalıştırılır

Uygulamayı çalıştırmak için aşağıdaki komutları sırasıyla çalıştırın:

1. `mitmproxy`'i başlatın:

    ```bash
    mitmproxy --mode reverse:http://localhost:8080 --listen-port 8082 -s mitmproxy_to_aiohttp.py
    ```

2. WAF uygulamasını başlatın:

    ```bash
    python3 proxy_waf.py
    ```

## Security Controls

Bu WAF uygulaması aşağıdaki potansiyel saldırı türlerini tespit edebilir ve engelleyebilir:

- SQL Injection saldırıları (`DROP TABLE`, `--`, `OR 1=1` gibi ifadeler içeren istekler)
- XSS (Cross-Site Scripting) saldırıları (`<script>` içeren istekler)
- mitmproxy modülü üzerinden "evil" içeren POST istekleri

## Technical Details

- WAF uygulaması port 8080'de çalışır
- mitmproxy port 8082'de çalışır ve istekleri WAF'a yönlendirir
- WAF, istekleri port 8001'de çalışan backend sunucuya iletir

## Dependencies

Projeyi çalıştırmadan önce aşağıdaki bağımlılıkların kurulu olduğundan emin olun:

- Python 3.x
- mitmproxy
- aiohttp
- requests

Bu bağımlılıkları `pip` kullanarak kurabilirsiniz:

```bash
pip install mitmproxy aiohttp requests
```

## BOTAŞ Internship Project

Bu proje, BOTAŞ stajım kapsamında bir Web Application Firewall (WAF) geliştirme çalışmasıdır.
