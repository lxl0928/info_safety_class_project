#!/usr/bin/env python3
# coding=utf-8

import os

from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, StaticFileHandler

from PyPDF2 import PdfFileReader
import urllib

from tinytag import TinyTag

import rsa_main as rsa
import dsa


def handle_mp3(filename):
    tag = TinyTag.get(filename)
    data_list = []
    data_list.append('the album is: %s.' % tag.album)
    data_list.append('the artist is: %s.' % tag.artist)
    data_list.append('the audio_offset is: %s.' % tag.audio_offset)
    data_list.append('the bitrate is: %s.' % tag.bitrate)
    data_list.append('the disc is: %s.' % tag.disc)
    data_list.append('the disc_total is: %s.' % tag.disc_total)
    data_list.append('the duration is: %s' % tag.duration)
    data_list.append('the filesize is: %s.' % tag.filesize)
    data_list.append('the genre is: %s.' % tag.genre)
    data_list.append('the samplerate is: %s.' % tag.samplerate)
    data_list.append('the title is: %s.' % tag.title)
    data_list.append('the track is: %s.' % tag.track)
    data_list.append('the track_total is: %s.' % tag.track_total)
    data_list.append('the year is: %s.' % tag.year)
    return '\n'.join(data_list)


def handle_pdf(fileName):
    pdfFile = PdfFileReader(open(fileName, 'rb'))
    docInfo = pdfFile.getDocumentInfo()
    str_list = ['[*] PDF MetaData For:' + str(fileName)]
    for metaItem in docInfo:
        str_list.append('[+]' + metaItem + ':' + docInfo[metaItem])
    return '\n'.join(str_list)


class IndexHandler(RequestHandler):

    def get(self):
        self.render("index.html")

    pass


class DigitalForensicsHandler(RequestHandler):

    def get(self):
        self.render("digital-forensics.html")

    def post(self):
        file_obj = self.request.files["file"][0]
        filename = file_obj["filename"]
        if filename.endswith(".pdf"):
            with open("/tmp/temp.pdf", "wb") as f:
                f.write(file_obj["body"])
            string = handle_pdf("/tmp/temp.pdf")
            infos = dict([info.replace(' ', '').split(':', 1)
                          for info in string.strip().split("\n")])
        elif filename.endswith(".mp3"):
            with open("/tmp/temp.mp3", "wb") as f:
                f.write(file_obj["body"])
            string = handle_mp3("/tmp/temp.mp3")
            infos = dict([info.replace(' ', '').split(':', 1)
                          for info in string.strip().split("\n")])
        else:
            file_suffix = filename[filename.rfind("."):]
            new_filename = "/tmp/temp" + file_suffix
            with open(new_filename, "wb") as f:
                f.write(file_obj["body"])
            string = os.popen("/home/timilong/class_pro/Info_Safety/02imageForensics/ImageForensics/exiftool " + new_filename).read()
            #string =os.popen("./exiftool " + new_filename).read()
            print("---------------------------")
            for info in string.strip().split("\n"):
                print("info: ", info)
            print("--------------------------")
            infos = dict([info.replace(' ', '').split(':', 1) for info in string.strip().split("\n")])
            gps_position = infos.get('GPSPosition')
            if (gps_position):
                gps_position = gps_position.replace('deg', ' ')
                url = 'www.google.cn/maps/place/' + gps_position
                url = urllib.parse.quote(url)
                url = ''.join(['<a href="http://', url,
                               '" target="_blank">点我查看谷歌位置信息</a><br>'])
                infos['GPSPosition'] = infos['GPSPosition'] + url
            else:
                infos["GPSPosition"] = "no gps position"
        self.render("tpl.html", infos=infos)

    pass


class DigitalSignatureHandler(RequestHandler):

    def get(self):
        self.render("digital-signature.html")

    def post(self):
        algorithm = self.get_argument("algorithm")
        algorithm_module = {"rsa": rsa, "dsa": dsa}.get(self.get_argument("algorithm"))
        fileobj = self.request.files["file"][0]
        print(fileobj)
        filename = fileobj["filename"]
        filebytes = fileobj["body"]
        pub_key, pri_key, sign = algorithm_module.encrypt(filebytes)
        pub_key_path = "/static/" + filename + "." + algorithm + ".pub"
        pri_key_path = "/static/" + filename + "." + algorithm + ".pri"
        sign_path = "/static/" + filename + "." + algorithm + ".sign"
        with open("." + pub_key_path, "wb") as f:
            f.write(pub_key)
        with open("." + pri_key_path, "wb") as f:
            f.write(pri_key)
        with open("." + sign_path, "wb") as f:
            f.write(sign)
        self.write({
            "pubkey": pub_key_path,
            "prikey": pri_key_path,
            "sign": sign_path,
        })

    pass


class DigitalCertificateHandler(RequestHandler):

    def get(self):
        self.render("digital-certificate.html")

    def post(self):
        algorithm = self.get_argument("algorithm")
        algorithm_module = {"rsa": rsa, "dsa": dsa}[algorithm]
        filebytes = self.request.files["file"][0]["body"]
        pubkey = self.request.files["pub"][0]["body"]
        sign = self.request.files["sign"][0]["body"]
        result = algorithm_module.decode(filebytes, sign, pubkey)
        print(result)
        self.write({"status": 200 if result else 400})

    pass


if __name__ == "__main__":
    routes = [(r"/", IndexHandler),
              (r"/static/(.*)", StaticFileHandler, {"path": "./static/"}),
              (r"/digital-forensics", DigitalForensicsHandler),
              (r"/digital-signature", DigitalSignatureHandler),
              (r"/digital-certificate", DigitalCertificateHandler)]
    app = Application(routes, **{
        "debug": True,
        "template_path": "templates",
        "static_path": "static",
    })
    app.listen(8000)
    print("服务已在: http://localhost:8000 启动")
    IOLoop.current().start()
