"""文件传输配置

定义分块传输的阈值、大小限制与 TTL 等参数。
使用 __slots__ 手动实现，避免 @dataclass 的隐式可变性。
"""


class FileTransferConfig:
    """文件传输配置

    控制文件分块传输行为：内联阈值、块大小、文件上限、块数上限、默认 TTL。
    """

    __slots__ = (
        "inline_threshold",
        "chunk_size",
        "max_file_size",
        "max_chunks",
        "default_ttl",
    )

    def __init__(
        self,
        inline_threshold: int = 4096,
        chunk_size: int = 1048576,
        max_file_size: int = 5368709120,
        max_chunks: int = 5120,
        default_ttl: int = 86400,
    ) -> None:
        # 小于此阈值直接内联到消息体
        self.inline_threshold: int = inline_threshold
        # 每个分块的字节大小
        self.chunk_size: int = chunk_size
        # 单个文件的最大字节数
        self.max_file_size: int = max_file_size
        # 单个文件最多拆成多少块
        self.max_chunks: int = max_chunks
        # 文件引用默认存活秒数
        self.default_ttl: int = default_ttl

    def should_inline(self, file_size: int) -> bool:
        """判断文件是否应内联传输（而非分块）"""
        return file_size <= self.inline_threshold

    def validate_size(self, file_size: int) -> None:
        """校验文件大小，超限则抛出 FileTooLargeError"""
        if file_size > self.max_file_size:
            # 延迟导入：避免 file_transfer 包与 exceptions 模块之间的循环依赖
            # pylint: disable=import-outside-toplevel
            from sip_protocol.exceptions import FileTooLargeError

            raise FileTooLargeError(file_size=file_size, max_size=self.max_file_size)
