import datetime
import json

line = '-------------------------------------'


def generate(output_path, result):
    time = datetime.datetime.now().strftime("%B %d, %Y (%H:%M)")
    generateTextFile(output_path, result, time)
    generateHTMLFile(output_path, result, time)
    generateJSON(output_path, result, time)


def generateTextFile(output_path, result, time):

    print(' > generate text file')

    f = open(output_path + "result.txt", "w")
    f.write('\n### Analysis Result ###\n')
    f.write(time+'\n\n')

    if len(result) == 0:
        f.write(line + '\n')
        f.write(' No APKs found.\n')

    for apk_name, apk_info in result.items():
        f.write(line + '\n')
        f.write('\nAPK: ' + apk_name + '\n')
        f.write('\nPermissions:' + '\n')
        for permission in apk_info['permissions']:
            f.write(' - ' + permission + '\n')
        if len(apk_info['permissions']) == 0:
            f.write(' - no permissions found\n')

        f.write('\nTrackers:' + '\n')
        for name, info in apk_info['trackers'].items():
            f.write(' - ' + name +
                    ' (' + info['website'] + ', ' + info['trigger'] + ')' + '\n')
        if len(apk_info['trackers'].keys()) == 0:
            f.write(' - no trackers found\n')

        if len(apk_info['info']) > 0:
            f.write('\nAdditional information:' + '\n')
            for info in apk_info['info']:
                f.write(' - ' + info + '\n')

        f.write('\n')
    f.write(line)

    f.close()


def generateHTMLFile(output_path, result, time):

    print(' > generate html file')

    f = open(output_path + "result.html", "w")
    f.write('<!doctype html><html><head><title>Analysis Result</title></head><body>')
    f.write('<h1 style="margin-left: 50px">Analysis Result</h1>')
    f.write('<h3 style="margin-left: 50px">' + time + '</h3>')

    if len(result) == 0:
        f.write('<h1 style="text-align: center; margin-top: 100px">No APKs found.</h1>')

    for apk_name, apk_info in result.items():

        f.write('<div style="background-color: #eeeeee; border: 2px solid black; border-radius: 15px; padding: 20px; margin: 50px 5vw 0 5vw">')
        f.write('<h2 style="margin-left: 25px">' + apk_name + '</h2>')

        # permissions
        f.write('<div style="display: flex;padding: 0 40px 0 40px">')
        f.write('<div style="flex: 1"><h3>Permissions:' + '</h3>')
        f.write('<ul>')
        for permission in apk_info['permissions']:
            f.write('<li>' + permission + '</li>')
        if len(apk_info['permissions']) == 0:
            f.write('<li>no permissions found</li>')
        f.write('</ul></div>')

        # trackers
        f.write('<div style="flex: 1"><h3>Trackers:' + '</h3>')
        f.write('<ul>')
        for name, info in apk_info['trackers'].items():
            f.write('<li><b>' + name +
                    '</b> (<a href="' + info['website'] + '" target="_blank">' + info['website'] + '</a>)')
            f.write('<ul><li>' + info['trigger'] + '</li></ul></li>')
        if len(apk_info['trackers'].keys()) == 0:
            f.write('<li>no trackers found</li>')
        f.write('</ul></div>')
        f.write('</div>')

        # additional info
        if len(apk_info['info']) > 0:
            f.write('<div style="padding: 0 40px 0 40px">')
            f.write('<h3>Additional information:</h3>')
            f.write('<ul>')
            for info in apk_info['info']:
                f.write('<li>' + info + '</li>')
            f.write('</ul>')
            f.write('</div>')

        f.write('</div>')

    f.write('</body></html>')
    f.close()


def generateJSON(output_path, result, time):
    print(' > generate json file')
    with open(output_path + "result.json", 'w') as f:
        json.dump(result, f, sort_keys=True, indent=4)
