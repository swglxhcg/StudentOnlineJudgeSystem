import logging
import sys
from typing import Any
from rich.console import Console
from rich.text import Text

class CtLogger(logging.Logger):
    """自定义日志类，支持 print 风格的日志输出"""
    def __init__(self, name: str, level: int = logging.INFO):
        super().__init__(name, level)
        self.enable = True  # 添加启用标志
        # 配置日志格式 [Time] [INFO] xxxx
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        # 默认添加控制台输出处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.addHandler(console_handler)

    def ctlog_print(self, *args: Any, level: str = "INFO", **kwargs: Any) -> None:
        """兼容 print 方法的日志输出
        :param args: 输出内容（支持多参数拼接）
        :param level: 日志级别，默认 INFO
        :param kwargs: 支持 print 的 sep/end 参数（如 sep="|", end="\n")
        """
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        message = sep.join(map(str, args)) + end.rstrip("\n")  # 拼接消息并移除默认换行
        log_level = getattr(logging, level.upper(), logging.INFO)  # 安全获取日志级别
        self.log(log_level, message)

    def info(self, *args: Any, **kwargs: Any) -> None:
        """INFO 级别日志"""
        self.ctlog_print(*args, level="INFO", **kwargs)

    def warning(self, *args: Any, **kwargs: Any) -> None:
        """WARNING 级别日志"""
        self.ctlog_print(*args, level="WARN", **kwargs)
        
    def warn(self, *args: Any, **kwargs: Any) -> None:
        """WARNING 级别日志"""
        self.ctlog_print(*args, level="WARN", **kwargs)

    def error(self, *args: Any, **kwargs: Any) -> None:
        """ERROR 级别日志"""
        self.ctlog_print(*args, level="ERROR", **kwargs)

    def debug(self, *args: Any, **kwargs: Any) -> None:
        """DEBUG 级别日志"""
        self.ctlog_print(*args, level="DEBUG", **kwargs)

    def critical(self, *args: Any, **kwargs: Any) -> None:
        """CRITICAL 级别日志"""
        self.ctlog_print(*args, level="CRITICAL", **kwargs)

class RichCtLogger(CtLogger):
    """使用 rich 库实现带颜色的日志输出"""
    def __init__(self, name: str, level: int = logging.INFO):
        super().__init__(name, level)
        self.enable = True  # 添加启用标志
        self.console = Console()
        # 移除默认的 console_handler
        self.handlers.clear()
        
    def ctlog_print(self, *args: Any, level: str = "INFO", **kwargs: Any) -> None:
        """兼容 print 方法的日志输出"""
        if not self.enable:  # 添加判断
            return
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        message = sep.join(map(str, args)) + end.rstrip("\n")
        
        # 创建带颜色的前缀
        prefix = Text()
        prefix.append("["+self._get_formatted_time()+"]", style=self._get_level_style(level))
        prefix.append(" ")
        prefix.append(f"[{level.upper()}]", style=self._get_level_style(level))
        prefix.append(" ")
        
        # 输出带颜色的前缀和默认颜色的消息
        self.console.print(prefix, end="")
        self.console.print(message)
    
    def _get_formatted_time(self) -> str:
        """获取格式化时间"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _get_level_style(self, level: str) -> str:
        """根据日志级别返回对应的颜色样式"""
        level = level.upper()
        if level == "INFO":
            return "bold blue"
        elif level == "WARN":
            return "bold yellow"
        elif level == "ERROR":
            return "bold red"
        return "bold white"

# 示例用法
if __name__ == "__main__":
    logger = CtLogger("demo_logger")
    logger.ctlog_print("Hello World")  # 输出 [Time] [INFO] Hello World
    logger.ctlog_print("Error:", "File not found", level="ERROR", sep="|")
    
    # 添加 rich 日志示例
    rich_logger = RichCtLogger("rich_demo_logger")
    rich_logger.ctlog_print("This is an info message")
    rich_logger.ctlog_print("This is a warning", level="WARN")
    rich_logger.ctlog_print("This is an error", level="ERROR")

    # 添加新方法使用示例
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")

    rich_logger.info("Rich info message")
    rich_logger.warning("Rich warning message")
    rich_logger.error("Rich error message")