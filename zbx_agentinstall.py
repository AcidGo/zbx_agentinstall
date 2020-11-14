# -*- coding: utf-8 -*-


# Author: AcidGo
# Usage:
#   mode: 指定安装的模式，可选如下：
#       - install: 安装，如果已安装则停止操作。
#       - update: 更新。
#       - force-install: 强制安装，即便已有安装，也会删除而再次进行安装。
#   url: 存放 zabbix-agent 的资源目录路径，确保该路径下存在 ZBX_AGENT_MENU 文件。
#   zbx_cnf_server: 安装后 zabbix-agent 关于 Server 的配置。
#   zbx_cnf_activeserver: 安装后 zabbix-agent 关于 ServerActive 的配置。
#   zbx_cnf_hostname: 安装后 zabbix-agent 关于 Hostname 的配置。
#   zbx_cnf_listenport: 安装后 zabbix-agent 关于 ListenPort 的配置。
#   zbx_cnf_logpath: 安装后 zabbix-agent 关于 LogFile 的配置。
#   zbx_cnf_userparameter: 修改 zabbix-agent 关于 UserParameter 的配置。


import platform, sys, os, time
import logging
import subprocess
import re
import requests

if sys.version_info.major == 2:
    import urlparse
else:
    from urllib import parse as urlparse

if platform.system().lower() == "windows":
    import win32serviceutil
    import shutil


# ########## CONFIG
LOGGING_LEVEL = "DEBUG"
ZBX_AGENT_MENU = "zbx_agent_menu.txt"
USE_ACCODE = False
WIN_ZBX_SERVICE_NAME = "Zabbix Agent"
WIN_ZBX_CONF_PATH = "C:\\zabbix_agent\\zabbix_agentd.win.conf"
WIN_ZBX_AGENT_EXE = "C:\\zabbix_agent\\zabbix_agentd.exe"
LNX_ZBX_SERVICE_NAME = "zabbix-agent"
LNX_ZBX_CONF_PATH = "/etc/zabbix/zabbix_agentd.conf"

WIN_SERVICE_STATUS_MAPPING = {
    -1: "NO_INSTALL",
    0: "UNKNOWN",
    1: "STOPPED",
    2: "START_PENDING",
    3: "STOP_PENDING",
    4: "RUNNING"
}

LNX_SERVICE_STATUS_MAPPING = {
    -1: "NO_INSTALL",
    0: "UNKNOWN",
    1: "INACTIVE",
    2: "ACTIVE"
}
# ########## EOF CONFIG


def easyops_init_logger(level):
    """初始化日志 Logger，将日志显示至运行终端。

    Args:
        level <str>: 日志级别。
    """
    logging.basicConfig(
        level = getattr(logging, level.upper()),
        format = "%(asctime)s [%(levelname)s] %(message)s",
        datefmt = "%Y-%m-%d %H:%M:%S"
    )


def zbx_agent_install(mode, url, zbx_cnf_server, zbx_cnf_activeserver, zbx_cnf_hostname, zbx_cnf_listenport, zbx_cnf_logpath, zbx_cnf_userparameter):
    """对 Linux、Windows 平台进行 zabbix-agent 安装。

    Args:
        mode: 安装模式，包括柔性安装、强制安装等。
        url: 存放 zabbix-agent 的资源目录路径。
        zbx_cnf_server: 安装后 zabbix-agent 关于 Server 的配置。
        zbx_cnf_activeserver: 安装后 zabbix-agent 关于 ServerActive 的配置。
        zbx_cnf_hostname: 安装后 zabbix-agent 关于 Hostname 的配置。
        zbx_cnf_listenport: 安装后 zabbix-agent 关于 ListenPort 的配置。
        zbx_cnf_logpath: 安装后 zabbix-agent 关于 LogFile 的配置。
    """
    in_args = set([i for i in locals()])
    args_info = "Input args: " + ", ".join(["{!s}:[{!s}]".format(i, j) for i, j in locals().items() if i in in_args])
    logging.info(args_info + ".")
    logging.info("Start check.")
    # 预检查
    tmp_res = precheck_zbx_agent_install(mode, url, zbx_cnf_server, zbx_cnf_activeserver, zbx_cnf_hostname, zbx_cnf_listenport, zbx_cnf_logpath, zbx_cnf_userparameter)
    if not tmp_res:
        logging.error("The check is not pass.EXIT.")
        raise Exception("Check Error.")
    else:
        mode = tmp_res[0]
        url = tmp_res[1]
        zbx_cnf_server = tmp_res[2]
        zbx_cnf_activeserver = tmp_res[3]
        zbx_cnf_hostname = tmp_res[4]
        zbx_cnf_listenport = tmp_res[5]
        zbx_cnf_logpath = tmp_res[6]
        zbx_cnf_userparameter = tmp_res[7]
    tmp_out = {}
    for j in [i for i in locals() if i in in_args]:
        tmp_out[j] = locals().get(j)
    logging.info("After check, the args change to: " + ", ".join(["{!s}:[{!s}]".format(i, j) for i, j in tmp_out.items()]) + ".")

    # 编辑配置的配置映射表
    edit_dict = {
        "Server": zbx_cnf_server,
        "ServerActive": zbx_cnf_activeserver,
        "Hostname": zbx_cnf_hostname,
        "ListenPort": zbx_cnf_listenport,
        "LogFile": zbx_cnf_logpath,
        "UserParameter": zbx_cnf_userparameter
    }
    hasedit = False
    for i in edit_dict:
        if isinstance(edit_dict[i], list):
            for j in edit_dict[i]:
                if j.strip():
                    hasedit = True
        else:
            if i.strip():
                hasedit = True
    if not hasedit:
        logging.info("No edit to change.")

    if not zbx_cnf_hostname:
        edit_dict["Hostname"] = get_preferred_ipaddres()
        if not edit_dict["Hostname"]:
            edit_dict["Hostname"] = ""

    logging.debug("The platform.system() is [{!s}].".format(platform.system().lower()))
    if platform.system().lower() == "windows":
        # 如果已安装
        if win_status_service(WIN_ZBX_SERVICE_NAME) != -1:
            if mode in ("force-install", "update"):
                cfg_path = WIN_ZBX_CONF_PATH
                hascfg = False
                if os.path.isfile(cfg_path):
                    from shutil import copyfile
                    from random import randint
                    tmpfile = os.path.join("C:\\", "zabbix_agent.win.conf.{!s}".format(randint(10000,99999)))
                    copyfile(cfg_path, tmpfile)
                    hascfg = True
                zbx_uninstall_win()
                zbx_install_win(url)
                if hascfg:
                    copyfile(tmpfile, cfg_path)
                if hasedit:
                    zbx_config_edit(cfg_path, edit_dict)
                zbx_restart_win()
                return 
            else:
                logging.error("The zabbix agent has already on the host.")
                raise Exception()
        else:
            zbx_install_win(url)
            cfg_path = WIN_ZBX_CONF_PATH
            if hasedit:
                zbx_config_edit(cfg_path, edit_dict)
            zbx_restart_win()
            return 

    elif platform.system().lower() == "linux":
        if lnx_status_servcie(LNX_ZBX_SERVICE_NAME) != -1:
            if mode == "force-install":
                cfg_path = LNX_ZBX_CONF_PATH
                hascfg = False
                if os.path.isfile(cfg_path):
                    from shutil import copyfile
                    from random import randint
                    tmpfile = os.path.join("/tmp", "zabbix_agent.win.conf.{!s}".format(randint(10000,99999)))
                    copyfile(cfg_path, tmpfile)
                    hascfg = True
                zbx_uninstall_lnx()
                zbx_install_lnx(url)
                if hascfg:
                    copyfile(tmpfile, cfg_path)
                if hasedit:
                    zbx_config_edit(cfg_path, edit_dict)
                zbx_restart_lnx()
                return 
            elif mode == "update":
                cfg_path = LNX_ZBX_CONF_PATH
                zbx_update_lnx(url)
                if hasedit:
                    zbx_config_edit(cfg_path, edit_dict)
                zbx_restart_lnx()
                return 
            else:
                logging.error("The zabbix agent has already on the host.")
                raise Exception()
        else:
            cfg_path = LNX_ZBX_CONF_PATH
            zbx_install_lnx(url)
            if hasedit:
                zbx_config_edit(cfg_path, edit_dict)
            zbx_restart_lnx()
            return 


def precheck_zbx_agent_install(mode, url, zbx_cnf_server, zbx_cnf_activeserver, zbx_cnf_hostname, zbx_cnf_listenport, zbx_cnf_logpath, zbx_cnf_userparameter):
    """对 zabbix-agent 安装操作前的预检查。
    """
    # 参数检查: url 可以访问
    if not url:
        logging.error("The url:[{!s}] is empty.".format(url))
        return False
    else:
        try:
            requests.get(url)
        except Exception as e:
            logging.error("Test urlopen the url:[{!s}], it get an error.".format(url))
            return False
    # 参数调整: 根据 menu 文件提取当前系统所需安装的 zabbix-agent 路径
    url_menu = urlparse.urljoin(url, ZBX_AGENT_MENU)
    logging.info("The url_menu is [{!s}].".format(url_menu))
    sysversion = get_sysversion()
    sysarch = get_sysarch()
    if platform.system().lower() == "windows":
        menu_prefix = "windows@@{!s}@@{!s}@@".format(sysversion, sysarch)
    elif platform.system().lower() == "linux":
        menu_prefix = "linux@@{!s}@@{!s}@@".format(sysversion, sysarch)
    try:
        r = requests.get(url_menu)
        menu_list = r.content.split('\n')
        # logging.debug(str(menu_list))
        pkg_agent = filter(lambda x: x.startswith(menu_prefix), menu_list)[0].split("@@")[-1]
        url_agent = urlparse.urljoin(url, pkg_agent)
    except Exception as e:
        logging.error("Get menu file is failed.")
        logging.error("The error: {!s}".format(e))
        return False
    if not url_agent:
        logging.error("Get the url_agent is empty, through menu_prefix:[{!s}].".format(menu_prefix))
        return False
    res_url = url_agent
    # 参数优化: zbx_cnf_userparameter 进行切割
    res_zbx_cnf_userparameter = [i.strip() for i in zbx_cnf_userparameter.split('\n')]
    # 参数优化: zbx_cnf_userparameter 输入中的 key 不能有重复
    # tmp_set = set()
    # for i in res_zbx_cnf_userparameter:
        # key_ = i.split(',')[0].strip()
        # if not key_:
            # logging.error("In UserParameter, key is empty.")
            # return False
        # if key_ in tmp_set:
            # logging.error("In UserParameter, it has same key:[{!s}].".format(key_))
            # return False
        # else:
            # tmp_set.add(key_)
    return mode, res_url, zbx_cnf_server, zbx_cnf_activeserver, zbx_cnf_hostname, zbx_cnf_listenport, zbx_cnf_logpath, res_zbx_cnf_userparameter


def get_sysversion():
    """获取当前操作系统的版本信息。

    Returns:
        <str> " ": 所有 windows 平台。
        <str> "el5": CentOS/RedHat 5。
        <str> "el6": CentOS/RedHat 6。
        <str> "el7": CentOS/RedHat 7。
    """
    if platform.system().lower() == "windows":
        return " "
    elif platform.system().lower() == "linux":
        res_tmp = subprocess.check_output(["uname", "-r"]).strip()
        res = re.search('el[0-9]', res_tmp).group()
        if res:
            return res
        else:
            logging.error("Cannot get sysversion from [{!s}].".format(res_tmp))
            raise Exception()


def get_sysarch():
    """获取当前操作系统的系统位数。

    Returns:
        <str> "32": 32 位操作系统。
        <str> "64": 64 位操作系统。
    """
    if platform.system().lower() == "windows":
        try:
            os.environ["PROGRAMFILES(X86)"]
            arch = "64"
        except:
            arch = "32"
        return arch
    elif platform.system().lower() == "linux":
        if subprocess.check_output(["uname", "-m"]).strip() == "x86_64":
            arch = "64"
        else:
            arch = "32"
        return arch


def zbx_install_lnx(path):
    """Linux(CentOS/RedHat) 下安装 zabbix-agent。

    Args:
        path: 安装资源包路径。
    """
    command_lst = ["rpm", "-ivh", path]
    if lnx_command_execute(command_lst):
        logging.info("zbx_install_lnx rpm successfully.")
    else:
        logging.error("zbx_install_lnx rpm failedly.")
        raise Exception()
    if get_sysversion() == "el7":
        command_lst = ["systemctl", "enable", LNX_ZBX_SERVICE_NAME]
    else:
        command_lst = ["chkconfig", "--add", LNX_ZBX_SERVICE_NAME]
        lnx_command_execute(command_lst)
        command_lst = ["chkconfig", LNX_ZBX_SERVICE_NAME, "on"]
    if lnx_command_execute(command_lst):
        logging.info("zbx_install_lnx enable successfully.")
    else:
        logging.error("zbx_install_lnx enable failedly.")
        raise Exception()


def zbx_install_win(path):
    """Windows 下安装 zabbix-agent。

    Args:
        path: 安装资源包路径。
    """
    import zipfile, StringIO
    r = requests.get(path, stream=True)
    z = zipfile.ZipFile(StringIO.StringIO(r.content))
    z.extractall("C:\\")
    zbx_agent_cnf = WIN_ZBX_CONF_PATH
    zbx_agent_exe = WIN_ZBX_AGENT_EXE
    command_lst = [zbx_agent_exe, "-c", zbx_agent_cnf, "-i"]
    pipe = subprocess.Popen(command_lst, stdout=subprocess.PIPE)
    logging.info(pipe.stdout.read().decode("utf-8").strip())
    time.sleep(2)
    command_lst = [zbx_agent_exe, "-c", zbx_agent_cnf, "-s"]
    pipe = subprocess.Popen(command_lst, stdout=subprocess.PIPE)
    logging.info(pipe.stdout.read().decode("utf-8").strip())


def zbx_uninstall_win():
    """卸载 Windows 上的 zabbix-agent 服务。
    """
    zbx_agent_cnf = WIN_ZBX_CONF_PATH
    zbx_agent_exe = WIN_ZBX_AGENT_EXE
    command_lst = [zbx_agent_exe, "-c", zbx_agent_cnf, "-x"]
    pipe = subprocess.Popen(command_lst, stdout=subprocess.PIPE)
    logging.info(pipe.stdout.read().decode("utf-8").strip())
    time.sleep(2)
    command_lst = [zbx_agent_exe, "-c", zbx_agent_cnf, "-d"]
    pipe = subprocess.Popen(command_lst, stdout=subprocess.PIPE)
    logging.info(pipe.stdout.read().decode("utf-8").strip())


def zbx_uninstall_lnx():
    """卸载 Linux(CentOS/RedHat) 上的 zabbix-agent 服务。
    """
    command_lst = ["yum", "remove", "-y", "zabbix-agent"]
    if lnx_command_execute(command_lst):
        logging.info("Uninstall zabbix-agent is successful.")
    else:
        logging.error("Uninstall zabbix-agent is failed.")
        raise Exception()


def zbx_update_lnx(path):
    """Linux(CentOS/RedHat) 下安装 zabbix-agent

    Args:
        path <string>: 安装资源包路径。
    """
    command_lst = ["rpm", "-Uvh", path]
    if lnx_command_execute(command_lst):
        logging.info("zbx_update_lnx rpm successfully.")
    else:
        logging.error("zbx_update_lnx rpm failedly.")
        raise Exception()
    if get_sysversion() == "el7":
        command_lst = ["systemctl", "enable", LNX_ZBX_SERVICE_NAME]
    else:
        command_lst = ["chkconfig", "--add", LNX_ZBX_SERVICE_NAME]
        lnx_command_execute(command_lst)
        command_lst = ["chkconfig", LNX_ZBX_SERVICE_NAME, "on"]
    if lnx_command_execute(command_lst):
        logging.info("zbx_update_lnx enable successfully.")
    else:
        logging.error("zbx_update_lnx enable failedly.")
        raise Exception()


def zbx_restart_lnx():
    """在 Linux(CentOS/RedHat) 上重启 zabbix-agent 服务。
    """
    if get_sysversion() == "el7":
        command_lst = ["systemctl", "restart", LNX_ZBX_SERVICE_NAME]
    else:
        command_lst = ["service", LNX_ZBX_SERVICE_NAME, "restart"]
    lnx_command_execute(command_lst)


def zbx_restart_win():
    """在 Windows 上重启 zabbix-agent 服务。
    """
    win32serviceutil.RestartService(WIN_ZBX_SERVICE_NAME)
    time.sleep(3)
    return win_status_service(WIN_ZBX_SERVICE_NAME)


def win_status_service(service_name):
    """查看 Windows 注册服务的状态信息。

    Args:
        service_name: 查看的服务名。
    Returns:
        <int>: 服务码，-1 为未注册，其他可见 WIN_SERVICE_STATUS_MAPPING。
    """
    try:
        status_code = win32serviceutil.QueryServiceStatus(service_name)[1]
    except Exception as e:
        # 服务未注册
        if hasattr(e, "winerror") and e.winerror == 1060:
            return -1
        else:
            raise e
    return status_code


def lnx_status_servcie(service_name):
    """查看 Linux 中服务的安装情况。

    Args:
        service_name: 查看的服务名。
    Returns:
        <int> -1: 未安装。
        <int> != -1: 其他情况。
    """
    if get_sysversion() == "el7":
        command_lst = ["systemctl", "status", service_name]
        try:
            subprocess.check_output(command_lst)
        except subprocess.CalledProcessError as e:
            if e.returncode == 4:
                return -1
            elif e.returncode == 3:
                return 1
            else:
                return 0
        else:
            return 2
    else:
        try:
            command_lst = ["service", service_name, "status"]
            subprocess.check_output(command_lst)
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                logging.debug("lnx_status_servcie returncode is [{!s}].".format(e.returncode))
                return -1
            else:
                logging.debug("lnx_status_servcie return is [{!s}] with CalledProcessError.".format(99))
                return 99
        else:
            logging.debug("lnx_status_servcie return is [{!s}] without CalledProcessError.".format(99))
            return 99


def get_preferred_ipaddres():
    """选择合适的当期主机内的 IP 地址。
    如果是 easyops 版本，则首先使用 EASYOPS_LOCAL_IP 变量；
    如果是非 easyops 版本，将使用报文协议获取所有IP，然后选择默认网关同网段的IP地址返回。

    Returns:
        <str> ip: 合适的IP地址，可能返回 None。
    """
    if "EASYOPS_LOCAL_IP" in globals() and globals().get("EASYOPS_LOCAL_IP") != "":
        return EASYOPS_LOCAL_IP

    import socket
    import fcntl
    import struct
    from sys import version_info

    def get_ip_address(ifname):
        """
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if version_info.major == 3:
            ifname_ = bytes(ifname[:15], "utf-8")
        else:
            ifname_ = ifname[:15]
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname_)
        )[20:24])

    ip_lst = []
    for net in list_all_netcards():
        ip_lst.append(get_ip_address(net))
    if len(ip_lst) == 0:
        return None
    if len(ip_lst) == 2 and '127.0.0.1' in ip_lst:
        return ip_lst[2 - ip_lst.index("127.0.0.1")]
    gateway = get_default_gateway()
    if not gateway:
        return None
    gateway_prefix = '.'.join(gateway.split('.')[0:-1])
    res = None
    for i in ip_lst:
        if i.startswith(gateway_prefix):
            res = i
            break
    return res


def list_all_netcards():
    """获取当前系统的所有可见网卡。

    Returns:
        <list> netcards_lst: 网卡集合。
    """
    import psutil
    if hasattr(psutil, "net_if_addrs"):
        addrs = psutil.net_if_addrs()
        return addrs.keys()
    else:
        import socket
        import fcntl
        import struct
        import array
        max_possible = 128
        bytes = max_possible * 32
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack("iL", fcntl.ioctl(
            s.fileno(),
            0x8912,
            struct.pack("iL", bytes, names.buffer_info()[0])
        ))[0]
        name_str = names.tostring()
        lst = []
        for i in range(0, outbytes, 40):
            name = name_str[i:i+16].split('\0', 1)[0]
            lst.append(name)
        return lst


def get_default_gateway():
    """获取当前的默认网关。
    """
    res = None
    if platform.system().lower() == "linux":
        res_tmp = subprocess.check_output(["ip", "-4", "route"]).strip().split(os.linesep)
        for i in res_tmp:
            if "default" in i:
                res = i.split()[2].strip()
    elif platform.system().lower() == "windows":
        logging.error("get_default_gateway not in windows.")
        pass
    return res


def zbx_config_edit(config_path, config_dict):
    """修改 zabbix-agent 配置文件的参数。

    Args:
        config_path: 需要修改的 zabbix-agent 的配置文件路径。
        config_dict: 需要修改的参数内容。
    """
    import re
    if len(filter(lambda x: config_dict.get(x, '') in ('', []), config_dict)) == len(config_dict):
        logging.info("No config to edit.")
        with open(config_path, "r") as f:
            for line in f:
                for i in config_dict:
                    tmp = re.search(r"^{!s} *= *(.*?)$".format(i), line)
                    if not tmp:
                        continue
                    else:
                        logging.info("Now config: {!s}.".format(line.strip()))
                        break
        return 
    if not os.path.isfile(config_path):
        logging.error("The config:[{!s}] is not a file not not exists.".format(config_path))
        raise Exception()
    if not os.access(config_path, os.W_OK):
        logging.error("The config:[{!s}] is not allow to write.".format(config_path))
        raise Exception()
    logging.info("Begin to chagne config.")
    conf_lst = []
    old_config_dict = {}
    if config_dict.get("UserParameter", None):
        userparameter_append = [i for i in config_dict["UserParameter"]]
        userparameter_change = []
        old_config_dict["UserParameter"] = []
    with open(config_path, "r") as f:
        for line in f:
            for i in config_dict:
                if not config_dict[i]:
                    continue
                tmp = re.search(r"^{!s} *= *(.*?)$".format(i), line)
                if not tmp:
                    continue
                else:
                    if i == "UserParameter":
                        # 如果 config_dict["UserParameter"] 中的所有元素为空，则跳过上层 for
                        for ii_1 in config_dict[i]:
                            if ii_1.strip() != "":
                                break
                        else:
                            continue
                        cnf_userparameter_key = "".join(line.strip().split('=')[1:]).split(',')[0].strip()
                        for j_value in config_dict[i]:
                            if cnf_userparameter_key == j_value.strip().split(',')[0].strip():
                                logging.debug("Catch userparameter_key:[{!s}].".format(cnf_userparameter_key))
                                logging.debug("It is [{!s}].".format(line.strip()))
                                # 如果 UserParameter 是带有 DEL 符号的，则需要删除
                                if j_value.strip().split(',')[-1].strip() == "DEL":
                                    logging.debug("For the userparameter_key:[{!s}], DEL it.".format(cnf_userparameter_key))
                                    userparameter_append.remove(j_value)
                                    line = "@@"
                                    break
                                else:
                                    old_line = line
                                    line = re.sub(r"^{!s} *= *(.*?)$".format(i), "{!s}={!s}".format(i, j_value), line)
                                    old_config_dict[i].append(tmp.group(1))
                                    userparameter_change.append((old_line.strip(), j_value.strip()))
                                    userparameter_append.remove(j_value)
                                    break
                    else:
                        old_config_dict[i] = tmp.group(1)
                        line = re.sub(r"^{!s} *= *(.*?)$".format(i), "{!s}={!s}".format(i, config_dict[i]), line)
                    break
            if line != "@@":
                conf_lst.append(line)
            else:
                logging.debug("Get the special symbol:[{!s}].".format(line.strip()))
    hassplit = 0 if conf_lst[-1].endswith(os.linesep) else 1
    # 某些可能存在上一步未匹配得到的修改配置，这里讲追加至尾部
    for i in config_dict:
        if i == "UserParameter":
            if len(filter(lambda x: x.strip() != "", userparameter_append)) > 0:
                for j in userparameter_append:
                    if j.strip().split(',')[-1].strip() == "DEL":
                        continue
                    conf_lst.append("{!s}={!s}".format(os.linesep*hassplit + i, str(j) + os.linesep))
                    userparameter_change.append(('', "UserParameter={!s}".format(j.strip())))
        elif i not in old_config_dict and config_dict[i]:
            conf_lst.append("{!s}={!s}".format(os.linesep*hassplit + i, str(config_dict[i]) + os.linesep))
            old_config_dict[i] = ""
    with open(config_path, "w") as f:
        for line in conf_lst:
            f.write(line)
    for i in old_config_dict:
        if i != "UserParameter":
            logging.info("Change {!s}={!s} -> {!s}".format(i, old_config_dict[i], config_dict[i]))
        else:
            for j in userparameter_change:
                logging.info("Change {!s} -> {!s}".format(j[0], j[1]))


def lnx_command_execute(command_lst):
    """在 Linux 平台执行命令。

    Args:
        command_lst: 命令列表，shell 下命令的空格分段形式。
    Returns:
        <bool> False: 执行返回非预期 exitcode。
        <bool> True: 执行返回预期 exitcode。
    """
    logging.info("---------- {!s} ----------".format(command_lst))
    try:
        res = subprocess.check_output(command_lst, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        for i in e.output.split('\n'):
            logging.error(i)
        logging.info("-"*30)
        return False
    for i in [i for i in res.split('\n') if not i.strip()]:
        logging.info(i)
    logging.info("-"*30)
    return True


if __name__ == "__main__":
    # ########## Self Test
    # INPUT_MODE = "install"
    # INPUT_URL = "url"
    # INPUT_ZBX_CNF_SERVER = "zbx_cnf_server"
    # INPUT_ZBX_CNF_ACTIVESERVER = "zbx_cnf_activeserver"
    # INPUT_ZBX_CNF_HOSTNAME = "zbx_cnf_hostname"
    # INPUT_ZBX_CNF_LISTENPORT = "zbx_cnf_listenport"
    # INPUT_ZBX_CNF_LOGPATH = "zbx_cnf_logpath"

    # zbx_agent_install(
      # mode = INPUT_MODE, 
      # url = INPUT_URL, 
      # zbx_cnf_server = INPUT_ZBX_CNF_SERVER, 
      # zbx_cnf_activeserver = INPUT_ZBX_CNF_ACTIVESERVER, 
      # zbx_cnf_hostname = INPUT_ZBX_CNF_HOSTNAME, 
      # zbx_cnf_listenport = INPUT_ZBX_CNF_LISTENPORT, 
      # zbx_cnf_logpath = INPUT_ZBX_CNF_LOGPATH,
      # zbx_cnf_userparameter = INPUT_ZBX_CNF_USERPARAMETER,
    # )
    # ########## EOF Self Tes
    easyops_init_logger("debug")

    try:
        zbx_agent_install(
          mode = INPUT_MODE, 
          url = INPUT_URL, 
          zbx_cnf_server = INPUT_ZBX_CNF_SERVER, 
          zbx_cnf_activeserver = INPUT_ZBX_CNF_ACTIVESERVER, 
          zbx_cnf_hostname = INPUT_ZBX_CNF_HOSTNAME, 
          zbx_cnf_listenport = INPUT_ZBX_CNF_LISTENPORT, 
          zbx_cnf_logpath = INPUT_ZBX_CNF_LOGPATH,
          zbx_cnf_userparameter = INPUT_ZBX_CNF_USERPARAMETER,
        )
    except Exception as e:
        logging.error("Runtime has error: {!s}.Please check.".format(e))
        exit(1)