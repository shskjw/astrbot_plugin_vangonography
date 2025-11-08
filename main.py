import os
import uuid
import base64
import shutil
import asyncio
from typing import Optional, Tuple
import aiohttp
from pathlib import Path

from astrbot.api import logger
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.core.message.components import Image as CompImage, File as CompFile, Reply, Plain

from . import vangonography_api

try:
    from astrbot.core.utils.session_waiter import session_waiter, SessionController
except ImportError:
    raise ImportError("您的 AstrBot 版本不支持 session_waiter, 插件无法运行。")
try:
    from astrbot.core.message.message_event_result import MessageChain
except ImportError:
    MessageChain = list


class FileWorkflow:
    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy
        self.session = aiohttp.ClientSession()

    async def _download(self, url: str):
        try:
            async with self.session.get(url, proxy=self.proxy, timeout=30) as response:
                response.raise_for_status()
                return await response.read()
        except Exception as e:
            logger.error(f"下载失败: {e}")
            return None

    async def _load_resource(self, source: str):
        loop = asyncio.get_running_loop()
        if Path(source).is_file():
            return await loop.run_in_executor(None, Path(source).read_bytes)
        if source.startswith('http'):
            return await self._download(source)
        if source.startswith('base64://'):
            return await loop.run_in_executor(None, base64.b64decode, source[9:])

    async def get_image(self, event: AstrMessageEvent) -> Optional[bytes]:
        for segment in event.message_obj.message:
            if isinstance(segment, Reply) and hasattr(segment, 'chain'):
                for sub_segment in segment.chain:
                    if isinstance(sub_segment, CompImage) and hasattr(sub_segment, 'url') and sub_segment.url:
                        if image_data := await self._load_resource(sub_segment.url):
                            return image_data
            if isinstance(segment, CompImage) and hasattr(segment, 'url') and segment.url:
                if image_data := await self._load_resource(segment.url):
                    return image_data
        return None

    async def get_file(self, event: AstrMessageEvent) -> Optional[Tuple[bytes, str]]:
        for segment in event.message_obj.message:
            if isinstance(segment, Reply) and hasattr(segment, 'chain'):
                for sub_segment in segment.chain:
                    if isinstance(sub_segment, CompFile) and hasattr(sub_segment, 'url') and sub_segment.url:
                        if file_data := await self._load_resource(sub_segment.url):
                            return file_data, getattr(sub_segment, 'name', 'file')
            if isinstance(segment, CompFile) and hasattr(segment, 'url') and segment.url:
                if file_data := await self._load_resource(segment.url):
                    return file_data, getattr(segment, 'name', 'file')
        return None, None

    async def terminate(self):
        if self.session and not self.session.closed:
            await self.session.close()


@register(
    'shskjw',
    'astrbot_plugin_vangonography',
    '一个通过图片隐写术来隐藏和提取文件的插件',
    '1.0.5' # Version bump
)
class VangonographyStar(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        
        # 最终修正方案：通过文件路径推断数据目录，确保兼容性
        # __file__ -> .../data/plugins/astrbot_plugin_vangonography/main.py
        # os.path.dirname(__file__) -> .../data/plugins/astrbot_plugin_vangonography
        current_plugin_dir = os.path.dirname(__file__)
        # os.path.basename(...) -> astrbot_plugin_vangonography
        plugin_name = os.path.basename(current_plugin_dir)
        # os.path.dirname(current_plugin_dir) -> .../data/plugins
        plugins_dir = os.path.dirname(current_plugin_dir)
        # os.path.dirname(plugins_dir) -> .../data
        data_root_dir = os.path.dirname(plugins_dir)
        # 构造最终的数据目录路径 -> .../data/datas/astrbot_plugin_vangonography
        plugin_data_dir = os.path.join(data_root_dir, 'datas', plugin_name)

        self.tmp_dir = os.path.join(plugin_data_dir, 'tmp_vangonography')
        os.makedirs(self.tmp_dir, exist_ok=True)
        self.iwf = FileWorkflow()
        self.timeout = 1200

    async def terminate(self):
        await self.iwf.terminate()
        if os.path.exists(self.tmp_dir):
            try:
                shutil.rmtree(self.tmp_dir)
            except Exception as e:
                logger.error(f"清理插件 {self.meta.name} 的临时目录失败: {e}")

    @filter.command('隐藏')
    async def hide_process(self, event: AstrMessageEvent):
        state = {"step": "awaiting_cover", "cover_path": None, "file_path": None,
                 "password": None, "temp_paths": [], "session_id": str(uuid.uuid4()), "retry_count": 0}

        await event.send(event.plain_result("请上传封面图片（支持引用消息）"))

        @session_waiter(timeout=self.timeout)
        async def interaction_waiter(controller: SessionController, next_event: AstrMessageEvent):
            loop = asyncio.get_running_loop()
            try:
                async def handle_media_request(media_type: str):
                    media_bytes, original_name = None, None
                    media_name_prompt = ""

                    if media_type == 'image':
                        media_bytes = await self.iwf.get_image(next_event)
                        media_name_prompt = '图片'
                    else:
                        file_data = await self.iwf.get_file(next_event)
                        if file_data and file_data[0]:
                            media_bytes, original_name = file_data
                        if not media_bytes:
                            media_bytes = await self.iwf.get_image(next_event)
                        media_name_prompt = '文件或图片'

                    if not media_bytes:
                        state["retry_count"] += 1
                        if state["retry_count"] >= 3:
                            await next_event.send(next_event.plain_result(f'多次未检测到{media_name_prompt}，操作已自动取消。'))
                            return "stop", None, None
                        else:
                            await next_event.send(next_event.plain_result(f'未检测到{media_name_prompt}，请重新上传。'))
                            return "continue", None, None

                    ext = "_cover.png" if media_type == 'image' else "_file_to_hide"
                    path = os.path.join(self.tmp_dir, f"{state['session_id']}{ext}")

                    await loop.run_in_executor(None, lambda: Path(path).write_bytes(media_bytes))
                    state["temp_paths"].append(path)
                    return "ok", path, original_name

                if state["step"] == "awaiting_cover":
                    result, path, _ = await handle_media_request('image')
                    if result == "continue": return
                    if result == "stop": controller.stop(); return
                    state["cover_path"] = path
                    state.update({"step": "awaiting_file", "retry_count": 0})
                    await next_event.send(next_event.plain_result("封面图收到。现在请上传要隐藏的文件（可以是任意格式，包括图片）。"))

                elif state["step"] == "awaiting_file":
                    result, path, name = await handle_media_request('file')
                    if result == "continue": return
                    if result == "stop": controller.stop(); return
                    state["file_path"] = path
                    state["original_filename"] = name
                    state.update({"step": "awaiting_filename", "retry_count": 0})
                    await next_event.send(next_event.plain_result(f"文件收到。请为这个文件命名（需要包含后缀），或直接发送以使用默认文件名「{name}」。"))

                elif state["step"] == "awaiting_filename":
                    filename = next_event.get_message_str().strip()
                    if not filename:
                        filename = state.get("original_filename", "default_file")
                    state["filename"] = filename
                    state.update({"step": "awaiting_password", "retry_count": 0})
                    await next_event.send(next_event.plain_result("文件名收到。需要加密吗？请发送密码或回复「不需要」"))

                elif state["step"] == "awaiting_password":
                    password = next_event.get_message_str().strip()
                    if password.lower() in ['不需要', '不用', 'no', '']:
                        password = None
                    await next_event.send(next_event.plain_result('收到。正在处理...'))
                    output_path = os.path.join(self.tmp_dir, f"{state['session_id']}_output.png")
                    state["temp_paths"].append(output_path)

                    await loop.run_in_executor(
                        None,
                        lambda: vangonography_api.hide_file_into_image(
                            cover_path=state["cover_path"],
                            file_path=state["file_path"],
                            file_name=state["filename"],
                            output_path=output_path,
                            encrypt=bool(password),
                            password=password
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
                logger.error(f"交互式隐藏失败: {e}", exc_info=True)
                await next_event.send(next_event.plain_result(f"处理失败: {e}"))
                controller.stop()

        try:
            await interaction_waiter(event)
        except TimeoutError:
            await event.send(event.plain_result("操作超时，已取消。"))
        finally:
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
            loop = asyncio.get_running_loop()

            try:
                if state["step"] == "awaiting_stego_image":
                    img_bytes = await self.iwf.get_image(next_event)
                    if not img_bytes:
                        state["retry_count"] += 1
                        if state["retry_count"] >= 3:
                            await next_event.send(next_event.plain_result('多次未检测到图片，操作已自动取消。'))
                            controller.stop()
                        else:
                            await next_event.send(next_event.plain_result('未检测到图片，请重新上传。'))
                            return
                    else:
                        img_path = os.path.join(self.tmp_dir, f"{session_id}_stego.png")
                        await loop.run_in_executor(None, lambda: Path(img_path).write_bytes(img_bytes))
                        state.update({"temp_paths": [img_path], "img_path": img_path,
                                      "step": "awaiting_password", "retry_count": 0})
                        await next_event.send(next_event.plain_result('图片收到。如果已加密，请输入密码，否则回复「不需要」。'))

                elif state["step"] == "awaiting_password":
                    password = next_event.get_message_str().strip()
                    if password.lower() in ['不需要', '不用', 'no', '']:
                        password = None
                    await next_event.send(next_event.plain_result('收到。正在提取...'))

                    try:
                        result_path = await loop.run_in_executor(
                            None,
                            lambda: vangonography_api.extract_file_from_image(
                                image_path=state["img_path"],
                                output_dir=self.tmp_dir,
                                password=password
                            )
                        )
                    except ValueError as ve:
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
                                message=[{"type": "file", "data": {"name": filename, "file": f"base64://{encoded_string}"}}]
                            )
                        except Exception as send_err:
                            logger.error(f"私聊发送文件失败: {send_err}")
                            await next_event.send(next_event.plain_result("私聊发送文件失败，请检查是否已添加好友或机器人是否有私聊权限。"))
                    else:
                        await next_event.send(next_event.plain_result("提取成功，但文件未能保存。"))
                    controller.stop()

            except Exception as e:
                logger.error(f"交互式提取失败: {e}", exc_info=True)
                await next_event.send(next_event.plain_result(f"处理失败: {e}"))
                controller.stop()

        try:
            await extraction_waiter(event)
        except TimeoutError:
            await event.send(event.plain_result("操作超时，已取消。"))
        finally:
            for path in state["temp_paths"]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception as e:
                        logger.error(f"清理临时文件失败 {path}: {e}")
        event.stop_event()
