# nessus_scan_api  
1.脚本说明  
自动化提交扫描任务，单个任务最大32个ip，可以分开提交，nessus可以并发扫描，根据机器硬件情况适量提交。  
2.add脚本中的两个说明  
说明1，86是一个自定义扫描策略，自定义策略完成后点击这个策略可以找到策略id，如图所示  
说明2，这个uuid也是对应自定义策略的，打开chrome的调试模式即可获得，如图所示  
3.扫描结果导出脚本  
nessus_export_html.py，下载扫描完的任务，导出报告，并且删除任务，由于home版本只能导出html或者csv文件，可以根据需要选择,
默认是html格式，如有需要请将脚本里所有html字眼改成csv即可，不支持pdf，切记。  
4.注意事项
nessus是支持多用户的，强烈建议用管理员创建扫描策略，新建普通用户提交任务，两个脚本里分别用了key认证，和用户名密码（session）认证
对应的用户都是同一个  
5.愉快的玩起来吧,基于整个脚本可以方便的用flask封装成api提交任务   
![image](https://github.com/weichenqi/nessus_scan_api/blob/master/11.png)  
![image](https://github.com/weichenqi/nessus_scan_api/blob/master/12.png)
