import os
import uuid
import base64
import tempfile
import shutil
import asyncio
from typing import Optional, Tuple
import aiohttp
from pathlib import Path
from PIL import Image

from astrbot import logger
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.core.message.components import Image as CompImage, File as CompFile, Reply, Plain

try:
    from astrbot.core.utils.session_waiter import session_waiter, SessionController
except ImportError:
    raise ImportError("您的 AstrBot 版本不支持 session_waiter, 插件无法运行。")
try:
    from astrbot.core.message.message_event_result import MessageChain
except ImportError:
    MessageChain = list

FILENAME_DELIMITER = b"<-F-N->"
DELIMITER = b"<-V-G->"


def _derive_key(p: str, s: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    k = PBKDF2HMAC(hashes.SHA256(), 32, s, 100000);
    return base64.urlsafe_b64encode(k.derive(p.encode()))


def encrypt_data(d: bytes, p: str) -> bytes:
    from cryptography.fernet import Fernet
    s = os.urandom(16);
    k = _derive_key(p, s);
    return s + Fernet(k).encrypt(d)


def decrypt_data(d: bytes, p: str) -> bytes:
    from cryptography.fernet import Fernet
    s, c = d[:16], d[16:];
    k = _derive_key(p, s);
    return Fernet(k).decrypt(c)


def _embed_data(imp: str, d: bytes, oup: str):
    im = Image.open(imp).convert('RGB')
    w, h = im.size
    bits = ''.join(f'{b:08b}' for b in (d + DELIMITER))

    # 自动计算是否需要放大
    required_pixels = -(-len(bits) // 3)
    current_pixels = w * h
    if required_pixels > current_pixels:
        scale = (required_pixels / current_pixels) ** 0.5
        new_w = int(w * scale) + 1
        new_h = int(h * scale) + 1
        im = im.resize((new_w, new_h))
        w, h = new_w, new_h

    idx = 0
    for y in range(h):
        for x in range(w):
            r, g, b = im.getpixel((x, y))
            if idx < len(bits): r = (r & ~1) | int(bits[idx]); idx += 1
            if idx < len(bits): g = (g & ~1) | int(bits[idx]); idx += 1
            if idx < len(bits): b = (b & ~1) | int(bits[idx]); idx += 1
            im.putpixel((x, y), (r, g, b))
            if idx >= len(bits): break
        if idx >= len(bits): break
    im.save(oup, 'PNG')


def hide_file_into_image(c_path: str, f_path: str, f_name: str, o_path: str, enc: bool = False, p: Optional[str] = None,
                         td: Optional[str] = None):
    cln, pay = False, b""
    if td is None: td, cln = tempfile.mkdtemp(), True
    try:
        # 同步文件读取
        with open(f_path, 'rb') as f:
            file_content = f.read()

        pay = f_name.encode('utf-8') + FILENAME_DELIMITER + file_content

        if enc:
            if not p: raise ValueError('加密需要密码')
            pay = encrypt_data(pay, p)
        _embed_data(c_path, pay, o_path)
    finally:
        if cln:
            try:
                shutil.rmtree(td)
            except:
                pass


def _extract_data(ip: str) -> bytes:
    im = Image.open(ip)
    w, h = im.size
    data_bits = []

    # LSB 隐写提取
    for y in range(h):
        for x in range(w):
            r, g, b = im.getpixel((x, y))
            data_bits.append(str(r & 1))
            data_bits.append(str(g & 1))
            data_bits.append(str(b & 1))

    # 将位串转换为字节
    byte_string = "".join(data_bits)
    data_bytes = bytearray()
    for i in range(0, len(byte_string) // 8 * 8, 8):
        byte = int(byte_string[i:i + 8], 2)
        data_bytes.append(byte)

    # 查找分隔符
    try:
        delimiter_index = data_bytes.index(DELIMITER)
        return bytes(data_bytes[:delimiter_index])
    except ValueError:
        logger.error("未找到文件分隔符，返回全部提取数据。")
        return bytes(data_bytes)


def extract_file_from_image(ip: str, od: str, p: Optional[str] = None) -> str:
    d = _extract_data(ip)
    if p:
        try:
            d = decrypt_data(d, p)
        except Exception as e:
            logger.error(f"解密失败: {e}")
            raise ValueError("解密失败，密码错误或文件已损坏。")

    try:
        filename_bytes, file_content = d.split(FILENAME_DELIMITER, 1)
        filename = filename_bytes.decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        logger.warning("无法解析文件名，将使用默认文件名。")
        ext = '.zip' if d.startswith(b'PK\x03\x04') else '.bin'
        filename = f'extracted_file_{uuid.uuid4().hex[:6]}{ext}'
        file_content = d

    op = os.path.join(od, filename)
    # 同步文件写入
    with open(op, 'wb') as f:
        f.write(file_content)
    return op


class FileWorkflow:
    def __init__(self, p: Optional[str] = None):
        self.proxy, self.session = p, aiohttp.ClientSession()

    async def _d(self, u: str):
        try:
            async with self.session.get(u, proxy=self.proxy, timeout=30) as r:
                r.raise_for_status();
                return await r.read()
        except Exception as e:
            logger.error(f"下载失败: {e}");
            return None

    async def _l(self, s: str):
        lp = asyncio.get_running_loop()
        if Path(s).is_file(): return await lp.run_in_executor(None, Path(s).read_bytes)
        if s.startswith('http'): return await self._d(s)
        if s.startswith('base64://'): return await lp.run_in_executor(None, base64.b64decode, s[9:])

    async def get_image(self, e: AstrMessageEvent) -> Optional[bytes]:
        for seg in e.message_obj.message:
            # Handle replied messages
            if isinstance(seg, Reply) and hasattr(seg, 'chain'):
                for s_chain in seg.chain:
                    if isinstance(s_chain, CompImage) and hasattr(s_chain, 'url') and s_chain.url:
                        if img := await self._l(s_chain.url): return img
            # Handle direct messages
            if isinstance(seg, CompImage) and hasattr(seg, 'url') and seg.url:
                if img := await self._l(seg.url): return img
        return None

    async def get_file(self, e: AstrMessageEvent) -> Optional[Tuple[bytes, str]]:
        for seg in e.message_obj.message:
            # Handle replied messages
            if isinstance(seg, Reply) and hasattr(seg, 'chain'):
                for s_chain in seg.chain:
                    if isinstance(s_chain, CompFile) and hasattr(s_chain, 'url') and s_chain.url:
                        if data := await self._l(s_chain.url):
                            return data, getattr(s_chain, 'name', 'file')
            # Handle direct messages
            if isinstance(seg, CompFile) and hasattr(seg, 'url') and seg.url:
                if data := await self._l(seg.url):
                    return data, getattr(seg, 'name', 'file')
        return None, None

    async def terminate(self):
        if self.session and not self.session.closed: await self.session.close()


@register(
    'shskjw',
    'astrbot_plugin_vangonography',
    '一个通过图片隐写术来隐藏和提取文件的插件',
    '1.0.2'
)
class VangonographyStar(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        # 在插件目录下创建临时文件夹
        self.tmp_dir = os.path.join(os.path.dirname(__file__), 'tmp_vangonography')
        os.makedirs(self.tmp_dir, exist_ok=True)
        self.iwf = FileWorkflow()
        self.timeout = 1200

    async def terminate(self):
        await self.iwf.terminate()

    @filter.command('隐藏')
    async def hide_process(self, event: AstrMessageEvent):
        state = {"step": "awaiting_cover", "cover_path": None, "file_path": None,
                 "password": None, "temp_paths": [], "session_id": str(uuid.uuid4()), "retry_count": 0}

        await event.send(event.plain_result("请上传封面图片（支持引用消息）"))

        @session_waiter(timeout=self.timeout)
        async def interaction_waiter(controller: SessionController, next_event: AstrMessageEvent):
            # 获取当前事件循环
            loop = asyncio.get_running_loop()

            try:
                async def handle_media_request(media_type: str):
                    media_bytes = None
                    media_name_prompt = ""

                    if media_type == 'image':
                        media_bytes = await self.iwf.get_image(next_event)
                        media_name_prompt = '图片'
                    else:  # 'file' type now handles both files and images
                        # First, try to get a formal file upload
                        file_data = await self.iwf.get_file(next_event)
                        if file_data and file_data[0]:
                            media_bytes = file_data[0]
                        # If not, try to get an image upload
                        if not media_bytes:
                            media_bytes = await self.iwf.get_image(next_event)
                        media_name_prompt = '文件或图片'

                    if not media_bytes:
                        state["retry_count"] += 1
                        if state["retry_count"] >= 3:
                            await next_event.send(
                                next_event.plain_result(f'多次未检测到{media_name_prompt}，操作已自动取消。'))
                            return "stop", None
                        else:
                            await next_event.send(next_event.plain_result(f'未检测到{media_name_prompt}，请重新上传。'))
                            return "continue", None

                    ext = "_cover.png" if media_type == 'image' else "_file_to_hide"
                    path = os.path.join(self.tmp_dir, f"{state['session_id']}{ext}")

                    await loop.run_in_executor(None, lambda: Path(path).write_bytes(media_bytes))
                    state["temp_paths"].append(path)
                    return "ok", path
                
                if state["step"] == "awaiting_cover":
                    result, path = await handle_media_request('image')
                    if result == "continue": return
                    if result == "stop": controller.stop(); return
                    state["cover_path"] = path
                    state.update({"step": "awaiting_file", "retry_count": 0})
                    await next_event.send(next_event.plain_result("封面图收到。现在请上传要隐藏的文件（可以是任意格式，包括图片）。"))

                elif state["step"] == "awaiting_file":
                    result, path = await handle_media_request('file')
                    if result == "continue": return
                    if result == "stop": controller.stop(); return
                    state["file_path"] = path
                    state.update({"step": "awaiting_filename", "retry_count": 0})
                    await next_event.send(
                        next_event.plain_result("文件收到。请为这个文件命名（需要包含后缀，例如：我的文档.zip 或 secret.png）。"))

                elif state["step"] == "awaiting_filename":
                    filename = next_event.get_message_str().strip()
                    if not filename:  # 防止用户发送空消息
                        await next_event.send(next_event.plain_result("文件名不能为空，请重新输入。"))
                        return
                    state["filename"] = filename
                    state.update({"step": "awaiting_password", "retry_count": 0})
                    await next_event.send(next_event.plain_result("文件名收到。需要加密吗？请发送密码或回复「不需要」"))

                elif state["step"] == "awaiting_password":
                    password = next_event.get_message_str().strip()
                    if password.lower() in ['不需要', '不用', 'no', '']: password = None
                    await next_event.send(next_event.plain_result('收到。正在处理...'))
                    output_path = os.path.join(self.tmp_dir, f"{state['session_id']}_output.png")
                    state["temp_paths"].append(output_path)

                    await loop.run_in_executor(
                        None,
                        lambda: hide_file_into_image(
                            state["cover_path"],
                            state["file_path"],
                            state["filename"],
                            output_path,
                            enc=bool(password),
                            p=password,
                            td=self.tmp_dir
                        )
                    )


                    image_bytes = await loop.run_in_executor(None, lambda: Path(output_path).read_bytes())
                    
                    encoded_string = base64.b64encode(image_bytes).decode('ascii')
                    
                    await next_event.send(MessageChain([
                        Plain('✅ 隐写完成，图片如下：'),
                        CompImage(file=f"base64://{encoded_string}")
                    ]))

                    controller.stop()

            except Exception as e:
                logger.error(f"交互式隐藏失败: {e}", exc_info=True);
                await next_event.send(next_event.plain_result(f"处理失败: {e}"));
                controller.stop()

        try:
            await interaction_waiter(event)
        except TimeoutError:
            await event.send(event.plain_result("操作超时，已取消。"))
        finally:
            # 发送完成后，清理临时文件
            for path in state["temp_paths"]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception as e:
                        logger.error(f"清理临时文件失败 {path}: {e}")
        event.stop_event()

    @filter.command('提取')
    async def extract_process(self, event: AstrMessageEvent):
        state = {"step": "awaiting_stego_image", "temp_paths": [], "retry_count": 0, "img_path": None}
        await event.send(event.plain_result('请上传包含隐藏文件的图片（支持引用消息）'))

        @session_waiter(timeout=self.timeout)
        async def extraction_waiter(controller: SessionController, next_event: AstrMessageEvent):
            session_id = str(uuid.uuid4())
            # 获取当前事件循环
            loop = asyncio.get_running_loop()

            try:
                if state["step"] == "awaiting_stego_image":
                    img_bytes = await self.iwf.get_image(next_event)
                    if not img_bytes:
                        state["retry_count"] += 1
                        if state["retry_count"] >= 3:
                            await next_event.send(next_event.plain_result('多次未检测到图片，操作已自动取消。'));
                            controller.stop()
                        else:
                            await next_event.send(next_event.plain_result('未检测到图片，请重新上传。'));
                            return
                    else:
                        img_path = os.path.join(self.tmp_dir, f"{session_id}_stego.png")

                        # 异步写入文件
                        await loop.run_in_executor(None, lambda: Path(img_path).write_bytes(img_bytes))

                        state.update({"temp_paths": [img_path], "img_path": img_path,
                                      "step": "awaiting_password", "retry_count": 0})
                        await next_event.send(
                            next_event.plain_result('图片收到。如果已加密，请输入密码，否则回复「不需要」。'))

                elif state["step"] == "awaiting_password":
                    password = next_event.get_message_str().strip()
                    if password.lower() in ['不需要', '不用', 'no', '']: password = None
                    await next_event.send(next_event.plain_result('收到。正在提取...'))

                    try:
                        result_path = await loop.run_in_executor(
                            None,
                            lambda: extract_file_from_image(
                                state["img_path"],  # ip
                                self.tmp_dir,  # od
                                password  # p
                            )
                        )
                    except ValueError as ve:
                        # 捕获解密失败或文件损坏的特定错误
                        await next_event.send(next_event.plain_result(f"提取失败：{ve}"))
                        controller.stop()
                        return
                        
                    state["temp_paths"].append(result_path)
                    filename = os.path.basename(result_path)

                    if os.path.exists(result_path):
                        await next_event.send(next_event.plain_result("✅ 提取完成，文件将私聊发送给您。"))

                        file_data = await loop.run_in_executor(None, Path(result_path).read_bytes)

                        encoded_string = base64.b64encode(file_data).decode('ascii')
                        bot = next_event.bot

                        try:
                            await bot.send_private_msg(
                                user_id=next_event.get_sender_id(),
                                message=[
                                    {
                                        "type": "file",
                                        "data": {
                                            "name": filename,
                                            "file": f"base64://{encoded_string}"
                                        }
                                    }
                                ]
                            )
                        except Exception as send_err:
                            logger.error(f"私聊发送文件失败: {send_err}")
                            await next_event.send(
                                next_event.plain_result("私聊发送文件失败，请检查是否已添加好友或机器人是否有私聊权限。"))

                    else:
                        await next_event.send(next_event.plain_result("提取成功，但文件未能保存。"))

                    controller.stop()

            except Exception as e:
                logger.error(f"交互式提取失败: {e}", exc_info=True);
                await next_event.send(next_event.plain_result(f"处理失败: {e}"));
                controller.stop()

        try:
            await extraction_waiter(event)
        except TimeoutError:
            await event.send(event.plain_result("操作超时，已取消。"))
        finally:
            # 清理临时文件
            for path in state["temp_paths"]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception as e:
                        logger.error(f"清理临时文件失败 {path}: {e}")
        event.stop_event()
