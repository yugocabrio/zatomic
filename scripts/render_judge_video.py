#!/usr/bin/env python3
"""Render the reviewed public screen checkpoints into a two-minute walkthrough.

This is an edited sequence of real screenshots, not continuous screen recording.
It never reads wallets, controls the browser, or synthesizes transaction states.
Requires ffmpeg/ffprobe and an explicit local font file; at most two threads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def render(manifest, output, font):
    data = json.loads(manifest.read_text())
    assert data['scope'] == 'actual isolated-chain screen checkpoints; waits omitted'
    assert sum(scene['seconds'] for scene in data['scenes']) == 120
    if not font.is_file():
        raise ValueError('an installed font file is required')
    output.parent.mkdir(parents=True, exist_ok=True)
    private = ROOT / '.local'
    private.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='video-render-', dir=private) as temporary:
        work = Path(temporary)
        shutil.copyfile(font, work / 'font.ttf')
        (work / 'scope.txt').write_text(
            'ACTUAL LOCAL CHAINS  /  Screen checkpoints; waits omitted  /  No public settlement claim')
        clips = []
        for index, scene in enumerate(data['scenes']):
            frame = (manifest.parent / scene['frame']).resolve()
            if not frame.is_relative_to(manifest.parent.resolve()):
                raise ValueError('frame must be in the reviewed artifact directory')
            if hashlib.sha256(frame.read_bytes()).hexdigest() != scene['sha256']:
                raise ValueError('reviewed screenshot changed')
            (work / 'title.txt').write_text(scene['title'])
            (work / 'caption.txt').write_text(scene['caption'])
            clip = f'clip-{index:02d}.mp4'
            filters = (
                'scale=1600:880:force_original_aspect_ratio=decrease:force_divisible_by=2,'
                'pad=1920:1080:(ow-iw)/2:60:color=0x17281f,setsar=1,'
                'drawtext=fontfile=font.ttf:textfile=title.txt:fontcolor=0xd3ef84:fontsize=30:x=80:y=16,'
                'drawtext=fontfile=font.ttf:textfile=caption.txt:fontcolor=white:fontsize=28:x=(w-tw)/2:y=970,'
                'drawtext=fontfile=font.ttf:textfile=scope.txt:fontcolor=0xabb6ae:fontsize=21:x=(w-tw)/2:y=1032'
            )
            run('ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-loop', '1',
                '-framerate', '12', '-i', str(frame), '-t', str(scene['seconds']),
                '-vf', filters, '-filter_threads', '1', '-c:v', 'libx264',
                '-preset', 'veryfast', '-crf', '21', '-threads', '2',
                '-pix_fmt', 'yuv420p', '-an', clip, cwd=work)
            clips.append(f"file '{clip}'")
        (work / 'clips.txt').write_text('\n'.join(clips) + '\n')
        run('ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat',
            '-safe', '1', '-i', 'clips.txt', '-c', 'copy', '-movflags', '+faststart',
            'complete.mp4', cwd=work)
        result = json.loads(subprocess.check_output(['ffprobe', '-v', 'error',
            '-show_entries', 'format=duration:stream=codec_name,width,height',
            '-of', 'json', str(work / 'complete.mp4')]))
        assert float(result['format']['duration']) == 120
        assert result['streams'] == [{'codec_name': 'h264', 'width': 1920, 'height': 1080}]
        (work / 'complete.mp4').replace(output)
    print(json.dumps({'file': str(output), 'duration_seconds': 120,
        'edited_screen_checkpoints': True, 'continuous_recording': False,
        'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--font', type=Path, required=True)
    args = parser.parse_args()
    render(args.manifest.resolve(), args.output.resolve(), args.font.resolve())
