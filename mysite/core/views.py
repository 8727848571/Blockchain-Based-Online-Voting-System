import logging
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.http import HttpResponse
from time import ctime
import hashlib

from .mine import generate_hash
from .models import PollBlockchain, UserProfile

log = logging.getLogger(__name__)
''' @login_required
def home(request):
    return render(request, 'home.html') '''


@login_required
def poll(request):
    log.debug("Hey there it works!!")
    abc = request.user.username
    #logging.warning(UserProfile.objects.filter(user=abc).values('isVoteCasted')[0]['isVoteCasted'])
    if UserProfile.objects.filter(user=abc).values('isVoteCasted')[0]['isVoteCasted']:
        return render(request, 'sucessVote.html')
    else:
        if request.method == 'POST':
            receiverId = request.POST.get('party_name')
            if receiverId != None:
                timeStampVote = str(ctime())
                votesCountInDb = PollBlockchain.objects.count()
                if votesCountInDb != 0:
                    prevHash = PollBlockchain.objects.filter(id=votesCountInDb).values('blockHash')[0]['blockHash']
                    #logging.warning(prevHash)
                else:
                    prevHash = 0

                blockHash, nonce = generate_hash(
                    receiverId, timeStampVote, prevHash)
                # logging.warning("BlockHash:"+blockHash+"\n Nonce:"+str(nonce))
                newBlock = PollBlockchain(receiverId=str(receiverId),
                                        timeStampVote=str(timeStampVote), prevHash=str(prevHash), blockHash=str(blockHash), nonce=str(nonce))
                newBlock.save()

                UserProfile.objects.filter(user=abc).update(isVoteCasted=True)
                #logging.warning(abc)
                return render(request, 'sucessVote.html')

    return render(request, 'poll.html')


def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            obj = UserProfile(user=username, isVoteCasted=False)
            obj.save()
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('poll')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})

@login_required
def verify(request):

    #receiverId, timestampVote, prevHash, blockHash, nonce are taken from DB for each row
    table = PollBlockchain.objects.values_list('receiverId', 'timeStampVote', 'prevHash', 'blockHash', 'nonce')
    #logging.warning(table)
    numRows= PollBlockchain.objects.count()

    for index, row in enumerate(table):
        concatValue= row[0] + row[1] + row[2] + row[4]
        hash_object = hashlib.sha256(concatValue.encode())
        resultantHash = hash_object.hexdigest()

        #logging.warning(concatValue)
        #logging.warning(resultantHash)
        if resultantHash != row[3]:
            print('Block ' + str(index + 1) + ' of check1 is tamperred')
            tamperingmessage = {'error' : 'Vote tampering detected.', 'detail': resultantHash + ' != ' + row[3], 'culprit': row[0], 'errblock': str(index + 1)}
            return render(request,'verify.html', tamperingmessage)

        if index>0 :
            if table[index - 1][3] != row[2] :
                print('Block ' + str(index + 1) + ' of check2 is tamperred')
                tamperingmessage = {'error' : 'Vote tampering detected.', 'detail': table[index - 1][3] + ' != ' + row[2], 'culprit': row[0], 'errblock': str(index + 1)}
                return render(request,'verify.html', tamperingmessage)

    bjpVote= PollBlockchain.objects.filter(receiverId='BJP').count()
    congVote= PollBlockchain.objects.filter(receiverId='CONGRESS').count()
    dmkVote= PollBlockchain.objects.filter(receiverId='DMK').count()
    aitcVote= PollBlockchain.objects.filter(receiverId='AITC').count()
    ysrVote= PollBlockchain.objects.filter(receiverId='YSR').count()
    shivsenaVote= PollBlockchain.objects.filter(receiverId='SHIVSENA').count()
    jduVote= PollBlockchain.objects.filter(receiverId='JDU').count()
    bjdVote= PollBlockchain.objects.filter(receiverId='BJD').count()
    bspVote= PollBlockchain.objects.filter(receiverId='BSP').count()
    notaVote= PollBlockchain.objects.filter(receiverId='NOTA').count()
  
    CountTable = {'content':[bjpVote,congVote,dmkVote,aitcVote,ysrVote,shivsenaVote,jduVote,bjdVote,bspVote,notaVote]}
    CountingResult = {'BJP':bjpVote,'CONGRESS':congVote,'DMK':dmkVote,'AITC':aitcVote,'YSR':ysrVote,'SHIVSENA':shivsenaVote,'JDU':jduVote,'BJD':bjdVote,'BSP':bspVote,'NOTA':notaVote}
    return render(request,'result.html', CountingResult)
