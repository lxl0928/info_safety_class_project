#! -*- coding: utf-8 -*-

from tinytag import TinyTag

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
    return '<br>'.join(data_list)
