import configparser
import os
class readConf(object):

    def conf_path(self):
        beside_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "set.conf")
        from_cwd = os.path.join(os.getcwd(), "config", "set.conf")
        if os.path.isfile(beside_file):
            return beside_file
        return from_cwd

    def parser(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read(self.conf_path(), encoding="utf-8")
        return config

    def GetwebsocketParam(self):
        return self.parser().get('websocket', 'port')

    def GetDBParam(self):
        return self.parser().get('db', 'url')

    def GetErpParam(self):
        config = self.parser()
        if not config.has_section('erp'):
            return {}
        return {
            'attendance_url': config.get('erp', 'attendance_url', fallback='').strip(),
            'webhook_secret': config.get('erp', 'webhook_secret', fallback='').strip(),
            'gateway_secret': config.get('erp', 'gateway_secret', fallback='').strip(),
        }
    def GetUploadParam(self):
        path_="C:/dynamicface/picture/"
        return  path_
if __name__ == "__main__":
    # config = configparser.ConfigParser()  # 创建对象
    # config.read("set.conf", encoding="utf-8")  # 读取配置文件，如果配置文件不存在则创建
    # # 查询类方法
    # secs = config.sections()  # 获取所有的节点名称
    # print("所有的节点名称:", secs)
    #
    # val = config.has_section('websocket')  # 检查指定节点是否存在，返回True或False
    # print("指定节点是否存在:", val)
    # val = config.has_option('websocket', 'port')  # 检查指定节点中是否存在某个key，返回True或False
    # print("指定节点中是否存在某个key:", val)
    # val = config.has_option('websocket', 'host')  # 检查指定节点中是否存在某个key，返回True或False
    # print("指定节点中是否存在某个key:", val)
    #
    # item_list = config.items('websocket')  # 获取指定节点的键值对
    # print("指定节点的键值对:", item_list)
    # val = config.get('websocket', 'host')  # 获取指定节点的指定key的value
    # print("指定节点的指定key的value:", val)
    #
    # val = config.get('db', 'url')  # 获取指定节点的指定key的value
    # print("指定节点的指定key的value:", val)

    read = readConf()
    print(read.GetwebsocketParam())
    print(read.GetDBParam())