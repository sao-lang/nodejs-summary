# Nodejs

## 时间处理

`js`核心语法中本来就有`Date`对象进行时间的处理，常用语法：

```typescript
// 获取时间对象，可以添加一个2022-08-17 11:12:12这样的字符串或者时间戳获取具体的时间
const date = new Date();
// 获取现在的时间
const now = Date.now();
// 获取时间戳
const timestamp = date.getTime();
// 设置一个时间
const newDate = date.setTime(106903290212367);
const y = date.getFullYear();
const m = date.getMonth() +1;
const d = date.getDate();
const h = date.getHours();
const min = date.getMinutes();
const s = date.getSeconds();
```

使用`dayjs`这样的工具库处理：

```typescript
import * as dayjs from 'dayjs';
const dateStr = dayjs(newDate()).formate('YYYY-MM-DD HH:mm:ss');
```

[dayjs文档](https://dayjs.fenxianglu.cn/)

# Python

## 时间处理

`Python`内置了`time` `datetime`来进行时间的相关操作

`time`常用`api`

```python
import time
# 获取时间戳
t1 = time.time()
# 将时间戳转换成一个时间元组，默认是当前时间的时间戳，如time.struct_time(tm_year=2022, tm_mon=8, tm_mday=21, tm_hour=19, tm_min=37, tm_sec=15, tm_wday=6, tm_yday=233, tm_isdst=0)
t2 = time.localtime()
# 将时间戳转成一个时间字符串，默认当前时间，如Sun Aug 21 19:41:31 2022
t3 = time.ctime()
# 将一个时间元组转成字符串，默认是当前的时间元组
t4 = time.asctime((2019, 1, 1, 9, 23, 30, 1, 1, 0))
# 将一个时间戳转成格林威治时间元组，默认是当前时间
t5 = time.gmtime()
# 接受一个时间元组，转成时间戳
t6 = time.mktime(time.localtime())
# 将一个时间元组格式化成指定格式的时间戳
t7 = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
# 将一个时间字符串转成时间元组
t8 = time.strptime(time.ctime())
```

`datetime`常用`api`

```python
import datetime
# 接受时分秒等参数，返回一个time对象，可以通过t10.hour t10.minute t10.second获取时分秒
t10 = datetime.time(18, 20, 52)
# 接受年月日等参数，返回一个date对象，可以通过t11.year t11.month t11.day获取年月日
t11 = datetime.date(2022,12,12)
# 返回当前的date对象
t12 = datetime.date.today()
# 返回一个datetime对象，接受年月日时分秒等参数，可以通过t13.year t13.month t13.day t13.hour t13.minute t13.second返回年月日时分秒
t13 = datetime.datetime(2022,12,12,12,12,12)
# 返回当前的datetime对象
t14 = datetime.datetime.now()
# 通过datetime.timedelta可以进行时间的加减
t15 = t14 + datetime.timedelta(days=6)
```

# Go

## 时间处理

主要涉及time包 

```go
import "time"

package main
// 获取当前的时间，如2022-08-21 20:47:12.2692562 +0800 CST m=+0.003917501
var t1 = time.Now()
// 获取年，其他月等成分也同样获取
var t2 = t1.Year()
// 将当前时间格式化为指定格式的字符串，注意格式模板得2006-01-02 15:03:04
var t3 = t1.Formate("2006-01-02 15:03:04")
func main() {
    
}
```
